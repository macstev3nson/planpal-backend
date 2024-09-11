require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');  // Add this line
const multer = require('multer');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());  // Add this line

// Connect to MongoDB using the environment variable
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Could not connect to MongoDB', err));

// User model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  phoneNumber: String,
  profileImage: String,
  password: { type: String, required: true },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  friendRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const User = mongoose.model('User', userSchema);

// Event model
const eventSchema = new mongoose.Schema({
  title: { type: String, required: true },
  dateTime: { type: Date, required: true },
  location: { type: String, required: true },
  spots: { type: Number, required: true },
  creator: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  attendees: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const Event = mongoose.model('Event', eventSchema);

// User registration route
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, phoneNumber } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      phoneNumber
    });

    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error registering user', error: error.message });
  }
});

// User login route
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Generate JWT using the environment variable
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ token, userId: user._id });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

// Auth middleware
const auth = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

  try {
    // Verify token using the environment variable
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Token is not valid' });
  }
};

// Protected route example
app.get('/api/user', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching user', error: error.message });
  }
});

// Create event
app.post('/api/events', auth, async (req, res) => {
  try {
    const { title, dateTime, location, spots } = req.body;
    const event = new Event({
      title,
      dateTime,
      location,
      spots,
      creator: req.user.userId
    });
    await event.save();
    res.status(201).json(event);
  } catch (error) {
    res.status(500).json({ message: 'Error creating event', error: error.message });
  }
});

// Get events (only user's and friends' events)
app.get('/api/events', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    const events = await Event.find({
      $or: [
        { creator: req.user.userId },
        { creator: { $in: user.friends } }
      ]
    }).populate('creator', 'username').populate('attendees', 'username');
    res.json(events);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching events', error: error.message });
  }
});

// Get single event
app.get('/api/events/:id', auth, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).populate('creator', 'username');
    if (!event) return res.status(404).json({ message: 'Event not found' });
    res.json(event);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching event', error: error.message });
  }
});

// Update event
app.put('/api/events/:id', auth, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ message: 'Event not found' });
    if (event.creator.toString() !== req.user.userId) return res.status(403).json({ message: 'Not authorized' });

    const { title, dateTime, location, spots } = req.body;
    event.title = title;
    event.dateTime = dateTime;
    event.location = location;
    event.spots = spots;

    await event.save();
    res.json(event);
  } catch (error) {
    res.status(500).json({ message: 'Error updating event', error: error.message });
  }
});

// Delete event
app.delete('/api/events/:id', auth, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ message: 'Event not found' });
    if (event.creator.toString() !== req.user.userId) return res.status(403).json({ message: 'Not authorized' });

    await event.deleteOne();
    res.json({ message: 'Event removed' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting event', error: error.message });
  }
});

// Delete an event
app.delete('/api/events/:eventId', auth, async (req, res) => {
  try {
    const event = await Event.findById(req.params.eventId);
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }

    // Check if the user is the creator of the event
    if (event.creator.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'You are not authorized to delete this event' });
    }

    await Event.findByIdAndDelete(req.params.eventId);
    res.json({ message: 'Event deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting event', error: error.message });
  }
});

// Set up multer for file upload
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/') // Make sure this folder exists
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname))
  }
});

const upload = multer({ storage: storage });

// Get user profile
app.get('/api/profile', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching profile', error: error.message });
  }
});

// Update user profile
app.put('/api/profile', auth, upload.single('profileImage'), async (req, res) => {
  try {
    console.log('Received update request:', req.body);
    console.log('File:', req.file);

    const { username, email, phoneNumber } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.username = username || user.username;
    user.email = email || user.email;
    user.phoneNumber = phoneNumber || user.phoneNumber;
    
    if (req.file) {
      user.profileImage = `/uploads/${req.file.filename}`;
    }

    await user.save();
    res.json(user);
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ message: 'Error updating profile', error: error.message });
  }
});

// Search users
app.get('/api/users/search', auth, async (req, res) => {
  try {
    const searchTerm = req.query.term;
    const users = await User.find({
      $or: [
        { username: new RegExp(searchTerm, 'i') },
        { email: new RegExp(searchTerm, 'i') }
      ]
    }).select('_id username email');
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Error searching users', error: error.message });
  }
});

// Send friend request
app.post('/api/friends/request', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    const friendId = req.body.friendId;

    // Check if the user is trying to add themselves
    if (user._id.toString() === friendId) {
      return res.status(400).json({ message: 'You cannot add yourself as a friend' });
    }

    // Check if they're already friends or if a request is pending
    if (user.friends.includes(friendId) || user.friendRequests.includes(friendId)) {
      return res.status(400).json({ message: 'Friend request already sent or user is already a friend' });
    }

    const friend = await User.findById(friendId);
    if (!friend) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if the friend has already sent a request to this user
    if (friend.friendRequests.includes(user._id)) {
      return res.status(400).json({ message: 'This user has already sent you a friend request' });
    }

    friend.friendRequests.push(user._id);
    await friend.save();

    res.json({ message: 'Friend request sent successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error sending friend request', error: error.message });
  }
});

// Accept friend request
app.post('/api/friends/accept', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    const friendId = req.body.friendId;

    if (!user.friendRequests.includes(friendId)) {
      return res.status(400).json({ message: 'No friend request from this user' });
    }

    const friend = await User.findById(friendId);
    if (!friend) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if they're already friends (shouldn't happen, but just in case)
    if (user.friends.includes(friendId) || friend.friends.includes(user._id)) {
      user.friendRequests = user.friendRequests.filter(id => id.toString() !== friendId);
      await user.save();
      return res.status(400).json({ message: 'You are already friends with this user' });
    }

    // Remove the friend request
    user.friendRequests = user.friendRequests.filter(id => id.toString() !== friendId);

    // Add each other as friends
    user.friends.push(friendId);
    friend.friends.push(user._id);

    await user.save();
    await friend.save();

    res.json({ message: 'Friend request accepted' });
  } catch (error) {
    res.status(500).json({ message: 'Error accepting friend request', error: error.message });
  }
});

// Get friend requests
app.get('/api/friends/requests', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate('friendRequests', 'username email');
    res.json(user.friendRequests);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching friend requests', error: error.message });
  }
});

// Get friends
app.get('/api/friends', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate('friends', 'username email');
    res.json(user.friends);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching friends', error: error.message });
  }
});

// Remove friend
app.delete('/api/friends/:friendId', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    const friendId = req.params.friendId;

    if (!user.friends.includes(friendId)) {
      return res.status(400).json({ message: 'This user is not your friend' });
    }

    const friend = await User.findById(friendId);
    if (!friend) {
      return res.status(404).json({ message: 'Friend not found' });
    }

    // Remove the friend from the user's friend list
    user.friends = user.friends.filter(id => id.toString() !== friendId);
    await user.save();

    // Remove the user from the friend's friend list
    friend.friends = friend.friends.filter(id => id.toString() !== req.user.userId);
    await friend.save();

    res.json({ message: 'Friend removed successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error removing friend', error: error.message });
  }
});

// RSVP to an event
app.post('/api/events/:eventId/rsvp', auth, async (req, res) => {
  try {
    const event = await Event.findById(req.params.eventId);
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }

    // Check if the user is already in the attendees list
    if (event.attendees.includes(req.user.userId)) {
      return res.status(400).json({ message: 'You have already RSVP\'d to this event' });
    }

    // Check if there are available spots
    if (event.attendees.length >= event.spots) {
      return res.status(400).json({ message: 'This event is already full' });
    }

    // Add the user to the attendees list
    event.attendees.push(req.user.userId);
    await event.save();

    res.json({ message: 'RSVP successful' });
  } catch (error) {
    res.status(500).json({ message: 'Error RSVPing to event', error: error.message });
  }
});

// Get number of pending friend requests
app.get('/api/friends/requests/count', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    const count = user.friendRequests.length;
    res.json({ count });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching friend request count', error: error.message });
  }
});

// Get number of pending events
app.get('/api/events/pending/count', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate('friends');
    const friendIds = user.friends.map(friend => friend._id);
    
    const pendingEventsCount = await Event.countDocuments({
      creator: { $in: friendIds },
      attendees: { $ne: req.user.userId },
      dateTime: { $gt: new Date() }
    });

    res.json({ count: pendingEventsCount });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching pending event count', error: error.message });
  }
});

// Serve uploaded files
app.use('/uploads', express.static('uploads'));

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));