/**
 * E-commerce Backend Server
 *
 * This is a simplified, self-contained Node.js server using Express,
 * Mongoose, and JWT for a complete e-commerce application with admin
 * and delivery admin functionality.
 *
 * To run this server:
 * 1. Make sure you have Node.js installed.
 * 2. Save this file as `server.js`.
 * 3. Run `npm init -y` in your terminal.
 * 4. Install dependencies: `npm install express mongoose jsonwebtoken bcryptjs dotenv cors razorpay`
 * 5. Create a `.env` file and add your credentials as instructed below.
 * 6. Start the server: `node server.js`
 *
 */

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const Razorpay = require('razorpay');

// Load environment variables from .env file
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// Razorpay instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// --- Database Connection ---
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB Connected...');
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
};
connectDB();

// --- Mongoose Schemas ---
const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  imageUrl: { type: String, required: true },
});

const OrderItemSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  name: { type: String, required: true },
  quantity: { type: Number, required: true },
  price: { type: Number, required: true },
});

const OrderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  razorpayOrderId: { type: String },
  items: [OrderItemSchema],
  totalPrice: { type: Number, required: true },
  status: { type: String, default: 'Pending' }, // 'Pending', 'Processing', 'Delivered', 'Returned', 'Canceled'
  createdAt: { type: Date, default: Date.now },
});

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  isDeliveryAdmin: { type: Boolean, default: false },
});

const Product = mongoose.model('Product', ProductSchema);
const User = mongoose.model('User', UserSchema);
const Order = mongoose.model('Order', OrderSchema);

// --- JWT Authentication Middleware ---
const auth = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

const authAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ msg: 'Admin access required' });
    }
    next();
  } catch (err) {
    res.status(500).send('Server Error');
  }
};

const authDeliveryAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || !user.isDeliveryAdmin) {
      return res.status(403).json({ msg: 'Delivery Admin access required' });
    }
    next();
  } catch (err) {
    res.status(500).send('Server Error');
  }
};


// --- API Endpoints ---

// User Registration
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User already exists' });
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ name, email, password: hashedPassword });
    await user.save();

    const payload = { user: { id: user.id, isAdmin: user.isAdmin, isDeliveryAdmin: user.isDeliveryAdmin } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
      if (err) throw err;
      res.json({ token, isAdmin: user.isAdmin, isDeliveryAdmin: user.isDeliveryAdmin });
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });
    
    const payload = { user: { id: user.id, isAdmin: user.isAdmin, isDeliveryAdmin: user.isDeliveryAdmin } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
      if (err) throw err;
      res.json({ token, isAdmin: user.isAdmin, isDeliveryAdmin: user.isDeliveryAdmin });
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// --- Product Routes ---
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

app.post('/api/products', auth, authAdmin, async (req, res) => {
  const { name, description, price, imageUrl } = req.body;
  try {
    const newProduct = new Product({ name, description, price, imageUrl });
    const product = await newProduct.save();
    res.json(product);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});


// --- Payment and Order Routes ---
app.post('/api/orders/pay', auth, async (req, res) => {
  const { cartItems, totalPrice } = req.body;
  if (cartItems.length === 0) return res.status(400).json({ msg: 'Cart is empty' });

  try {
    const options = {
      amount: totalPrice * 100, // Razorpay amount in paise
      currency: "INR",
      receipt: `receipt_${req.user.id}`,
    };

    const razorpayOrder = await razorpay.orders.create(options);

    const newOrder = new Order({
      user: req.user.id,
      razorpayOrderId: razorpayOrder.id,
      items: cartItems.map(item => ({
        product: item._id,
        name: item.name,
        quantity: item.quantity,
        price: item.price,
      })),
      totalPrice,
      status: 'Processing',
    });

    await newOrder.save();
    res.json({ razorpayOrder });

  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get a user's order history
app.get('/api/orders/my-orders', auth, async (req, res) => {
  try {
    const orders = await Order.find({ user: req.user.id }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// Cancel a user's order
app.put('/api/orders/:id/cancel', auth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ msg: 'Order not found' });

    // Check if the order belongs to the authenticated user
    if (order.user.toString() !== req.user.id) {
      return res.status(401).json({ msg: 'Not authorized to cancel this order' });
    }

    // Only allow cancellation for 'Processing' or 'Pending' orders
    if (order.status !== 'Processing' && order.status !== 'Pending') {
      return res.status(400).json({ msg: 'Order cannot be canceled at this stage' });
    }

    order.status = 'Canceled';
    await order.save();
    res.json(order);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});


// --- Admin Panel Routes ---
app.get('/api/admin/dashboard', auth, authAdmin, async (req, res) => {
  try {
    const productCount = await Product.countDocuments();
    const deliveredOrdersCount = await Order.countDocuments({ status: 'Delivered' });
    const returnedOrdersCount = await Order.countDocuments({ status: 'Returned' });
    const pendingOrdersCount = await Order.countDocuments({ status: 'Pending' });
    const processingOrdersCount = await Order.countDocuments({ status: 'Processing' });
    const totalOrdersCount = await Order.countDocuments();

    res.json({
      productCount,
      totalOrders: totalOrdersCount,
      deliveredOrders: deliveredOrdersCount,
      returnedOrders: returnedOrdersCount,
      pendingOrders: pendingOrdersCount,
      processingOrders: processingOrdersCount,
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// Get all orders for admin view
app.get('/api/admin/orders', auth, authAdmin, async (req, res) => {
  try {
    // Populate user and item details for a richer admin view
    const orders = await Order.find().populate('user', 'name email').sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// --- Delivery Admin Routes ---
app.get('/api/delivery/orders', auth, authDeliveryAdmin, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

app.put('/api/delivery/orders/:id/status', auth, authDeliveryAdmin, async (req, res) => {
  const { newStatus } = req.body;
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ msg: 'Order not found' });

    order.status = newStatus;
    await order.save();
    res.json(order);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// Start the server
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
