const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const dns = require('dns'); // <-- ADDED: fixes "dns is not defined"

dotenv.config();

// ========== CREATE UPLOADS FOLDER IF NOT EXISTS ==========
const uploadDir = path.join(__dirname, 'uploads', 'cars');
fs.mkdirSync(uploadDir, { recursive: true });

// ========== MONGODB CONNECTION ==========
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
  console.error('❌ MONGODB_URI is not defined in .env');
  process.exit(1);
}

// Optional: use Google DNS if you face resolution issues
dns.setServers(['8.8.8.8', '8.8.4.4']);

mongoose.connect(mongoUri, {
  family: 4, // Force IPv4
})
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  });

// ========== MODELS ==========
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, 'Please add a valid email']
  },
  password: { type: String, required: true, minlength: 6, select: false },
  phone: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  drivingLicense: { number: String, expiryDate: Date },
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);

const carSchema = new mongoose.Schema({
  make: { type: String, required: true, trim: true },
  model: { type: String, required: true, trim: true },
  year: { type: Number, required: true, min: 2000, max: 2025 },
  type: { type: String, required: true, enum: ['sedan', 'suv', 'hatchback', 'truck', 'van', 'luxury'] },
  transmission: { type: String, enum: ['automatic', 'manual'], default: 'automatic' },
  fuelType: { type: String, enum: ['petrol', 'diesel', 'electric', 'hybrid'], default: 'petrol' },
  seatingCapacity: { type: Number, required: true, min: 2, max: 15 },
  luggageCapacity: { type: Number, default: 3 },
  features: [{ type: String }],
  images: [{ type: String }],
  pricePerDay: { type: Number, required: true, min: 0 },
  pricePerWeek: { type: Number, min: 0 },
  pricePerMonth: { type: Number, min: 0 },
  isAvailable: { type: Boolean, default: true },
  location: { type: String, required: true },
  rating: { type: Number, default: 0, min: 0, max: 5 },
  reviewCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const Car = mongoose.model('Car', carSchema);

const bookingSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
  car: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'Car' },
  pickupDate: { type: Date, required: true },
  returnDate: { type: Date, required: true },
  pickupLocation: { type: String, required: true },
  returnLocation: { type: String, required: true },
  totalDays: { type: Number, required: true },
  totalPrice: { type: Number, required: true },
  paymentMethod: { type: String, enum: ['cod', 'online'], default: 'cod' },
  paymentStatus: { type: String, enum: ['pending', 'paid', 'refunded'], default: 'pending' },
  bookingStatus: { type: String, enum: ['pending', 'confirmed', 'completed', 'cancelled'], default: 'pending' },
  notes: { type: String }
}, { timestamps: true });

const Booking = mongoose.model('Booking', bookingSchema);

// ========== MIDDLEWARE ==========
// Auth middleware
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select('-password');
      next();
    } catch (error) {
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  }
  if (!token) {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

const admin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ message: 'Not authorized as admin' });
  }
};

// Multer upload middleware
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);
  if (extname && mimetype) cb(null, true);
  else cb(new Error('Only images are allowed'), false);
};
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter
});

// ========== CONTROLLERS ==========
const generateToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '30d' });

const registerUser = async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });
    const user = await User.create({ name, email, password, phone });
    res.status(201).json({
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      token: generateToken(user._id)
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');
    if (user && (await user.matchPassword(password))) {
      res.json({
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        token: generateToken(user._id)
      });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Car Controllers
const getCars = async (req, res) => {
  try {
    const { type, location, minPrice, maxPrice } = req.query;
    const filter = {};
    if (type) filter.type = type;
    if (location) filter.location = location;
    if (minPrice || maxPrice) {
      filter.pricePerDay = {};
      if (minPrice) filter.pricePerDay.$gte = Number(minPrice);
      if (maxPrice) filter.pricePerDay.$lte = Number(maxPrice);
    }
    const cars = await Car.find(filter);
    res.json(cars);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getCarById = async (req, res) => {
  try {
    const car = await Car.findById(req.params.id);
    if (car) res.json(car);
    else res.status(404).json({ message: 'Car not found' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const createCar = async (req, res) => {
  try {
    const carData = req.body;
    if (req.files) {
      carData.images = req.files.map(file => `/uploads/cars/${file.filename}`);
    }
    const car = await Car.create(carData);
    res.status(201).json(car);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const updateCar = async (req, res) => {
  try {
    const car = await Car.findById(req.params.id);
    if (!car) return res.status(404).json({ message: 'Car not found' });
    Object.assign(car, req.body);
    await car.save();
    res.json(car);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const deleteCar = async (req, res) => {
  try {
    const car = await Car.findById(req.params.id);
    if (!car) return res.status(404).json({ message: 'Car not found' });
    await car.deleteOne();
    res.json({ message: 'Car removed' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Booking Controllers
const createBooking = async (req, res) => {
  try {
    const { carId, pickupDate, returnDate, pickupLocation, returnLocation, paymentMethod, notes } = req.body;
    const pickup = new Date(pickupDate);
    const returnD = new Date(returnDate);
    const totalDays = Math.ceil((returnD - pickup) / (1000 * 60 * 60 * 24));
    const car = await Car.findById(carId);
    if (!car) return res.status(404).json({ message: 'Car not found' });
    const totalPrice = car.pricePerDay * totalDays;
    const booking = new Booking({
      user: req.user._id,
      car: carId,
      pickupDate,
      returnDate,
      pickupLocation,
      returnLocation,
      totalDays,
      totalPrice,
      paymentMethod: paymentMethod || 'cod',
      paymentStatus: paymentMethod === 'online' ? 'paid' : 'pending',
      bookingStatus: 'pending',
      notes: notes || ''
    });
    const createdBooking = await booking.save();
    res.status(201).json(createdBooking);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getUserBookings = async (req, res) => {
  try {
    const bookings = await Booking.find({ user: req.user._id })
      .populate('car', 'make model images pricePerDay')
      .sort({ createdAt: -1 });
    res.json(bookings);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getAllBookings = async (req, res) => {
  try {
    const bookings = await Booking.find()
      .populate('user', 'name email phone')
      .populate('car', 'make model images')
      .sort({ createdAt: -1 });
    res.json(bookings);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const updateBookingStatus = async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
    if (!booking) return res.status(404).json({ message: 'Booking not found' });
    booking.bookingStatus = req.body.bookingStatus || booking.bookingStatus;
    booking.paymentStatus = req.body.paymentStatus || booking.paymentStatus;
    const updatedBooking = await booking.save();
    res.json(updatedBooking);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const cancelBooking = async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
    if (!booking) return res.status(404).json({ message: 'Booking not found' });
    if (booking.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Not authorized' });
    }
    booking.bookingStatus = 'cancelled';
    const updatedBooking = await booking.save();
    res.json(updatedBooking);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// ========== EXPRESS APP ==========
const app = express();

// Body parser
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Enable CORS
app.use(cors());

// Security headers
app.use(helmet());

// Dev logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Static folder for uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ========== ROUTES ==========
// Auth routes
app.post('/api/auth/register', registerUser);
app.post('/api/auth/login', loginUser);
app.get('/api/auth/profile', protect, getUserProfile);

// Car routes
app.get('/api/cars', getCars);
app.get('/api/cars/:id', getCarById);
app.post('/api/cars', protect, admin, upload.array('images', 5), createCar);
app.put('/api/cars/:id', protect, admin, updateCar);
app.delete('/api/cars/:id', protect, admin, deleteCar);

// Booking routes
app.post('/api/bookings', protect, createBooking);
app.get('/api/bookings', protect, getUserBookings);
app.get('/api/bookings/admin', protect, admin, getAllBookings);
app.put('/api/bookings/:id', protect, admin, updateBookingStatus);
app.put('/api/bookings/:id/cancel', protect, cancelBooking);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server is running' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ========== START SERVER ==========
const PORT = process.env.PORT || 5000;

// MongoDB is already connected above; we just need to start listening.
app.listen(PORT, () => {
  console.log(`🚀 Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
});