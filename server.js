
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const { spawn } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'namdhari8727@gmail.com,hakunamatatabot2@gmail.com')
    .split(',')
    .map(email => email.trim().toLowerCase())
    .filter(Boolean);

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session setup
app.use(session({
    secret: process.env.SESSION_SECRET || 'apnakitchen_secret',
    resave: false,
    saveUninitialized: false
}));

// Database Connection
const mongoURI = process.env.MONGO_URI;
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected successfully.'))
    .catch(err => console.error('MongoDB connection error:', err));

// --- MODELS ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    resetOtpHash: String,
    resetOtpExpiresAt: Date
});
const User = mongoose.model('User', userSchema);

const recipeSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: String,
    ingredients: { type: String, required: true },
    instructions: { type: String, required: true },
    category: { type: String, default: 'uncategorized' },
    imageUrl: String,
    youtubeUrl: String,
    username: String,
    rating: { type: Number, default: 0 },
    ratings: [{
        username: String,
        value: Number
    }],
    comments: [{
        username: String,
        text: String,
        createdAt: { type: Date, default: Date.now }
    }],
    likes: [{ type: String }],
    createdAt: { type: Date, default: Date.now }
});
const Recipe = mongoose.model('Recipe', recipeSchema);

const followSchema = new mongoose.Schema({
    followerUsername: { type: String, required: true },
    channelUsername: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
followSchema.index({ followerUsername: 1, channelUsername: 1 }, { unique: true });
const Follow = mongoose.model('Follow', followSchema);

function recipeResponse(recipe, username) {
    const recipeObject = recipe.toObject();
    recipeObject.likeCount = recipe.likes ? recipe.likes.length : 0;
    recipeObject.isLiked = Boolean(username && recipe.likes && recipe.likes.includes(username));
    const userRating = username && recipe.ratings
        ? recipe.ratings.find(rating => rating.username === username)
        : null;
    recipeObject.userRating = userRating ? userRating.value : 0;
    return recipeObject;
}

function isAdminEmail(email) {
    return Boolean(email && ADMIN_EMAILS.includes(email.toLowerCase()));
}

async function isAdminUsername(username) {
    if (!username) return false;
    const user = await User.findOne({ username });
    return Boolean(user && (user.isAdmin || isAdminEmail(user.email)));
}

async function canManageRecipe(recipe, username) {
    return Boolean(recipe && username && (recipe.username === username || await isAdminUsername(username)));
}

function normalizeEmail(email) {
    return email ? email.trim().toLowerCase() : '';
}

function generateOtp() {
    return String(Math.floor(100000 + Math.random() * 900000));
}

async function deliverOtpEmail(email, otp) {
    const smtpHost = process.env.SMTP_HOST;
    const smtpPort = Number(process.env.SMTP_PORT || 587);
    const smtpUser = process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASS;
    const mailFrom = process.env.MAIL_FROM || smtpUser;

    if (!smtpHost || !smtpUser || !smtpPass || !mailFrom) {
        throw new Error('SMTP email settings are missing.');
    }

    const subject = 'Your Apna Kitchen password reset OTP';
    const body = `Your Apna Kitchen password reset OTP is ${otp}. It expires in 10 minutes.`;
    const quoteForPowerShell = value => String(value).replace(/'/g, "''");
    const script = `
        $securePassword = ConvertTo-SecureString '${quoteForPowerShell(smtpPass)}' -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential('${quoteForPowerShell(smtpUser)}', $securePassword)
        Send-MailMessage -From '${quoteForPowerShell(mailFrom)}' -To '${quoteForPowerShell(email)}' -Subject '${quoteForPowerShell(subject)}' -Body '${quoteForPowerShell(body)}' -SmtpServer '${quoteForPowerShell(smtpHost)}' -Port ${smtpPort} -UseSsl -Credential $credential
    `;

    await new Promise((resolve, reject) => {
        const mailProcess = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], {
            windowsHide: true
        });
        let errorOutput = '';

        mailProcess.stderr.on('data', data => {
            errorOutput += data.toString();
        });

        mailProcess.on('error', reject);
        mailProcess.on('close', code => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(errorOutput || `Email process exited with code ${code}`));
            }
        });
    });
}

function normalizeYoutubeUrl(url) {
    if (!url || !url.trim()) return '';
    const value = url.trim();
    try {
        const parsed = new URL(value);
        const host = parsed.hostname.toLowerCase().replace(/^www\./, '');
        const allowedHosts = ['youtube.com', 'm.youtube.com', 'youtu.be'];
        if (!allowedHosts.includes(host)) return null;
        if (host === 'youtu.be' && parsed.pathname.length > 1) return parsed.toString();
        if (host.endsWith('youtube.com') && (parsed.pathname === '/watch' || parsed.pathname === '/results' || parsed.pathname.startsWith('/shorts/'))) {
            return parsed.toString();
        }
        return null;
    } catch (error) {
        return null;
    }
}

async function isImageSafe(file) {
    if (!file) return { safe: true };
    if (!file.mimetype || !file.mimetype.toLowerCase().startsWith('image/')) {
        return { safe: false, message: 'Only image uploads are allowed.' };
    }

    const moderationUrl = process.env.IMAGE_MODERATION_URL;
    if (!moderationUrl || typeof fetch !== 'function') {
        return { safe: true };
    }

    const fs = require('fs/promises');
    const imageBase64 = await fs.readFile(file.path, { encoding: 'base64' });
    const response = await fetch(moderationUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            filename: file.originalname,
            mimetype: file.mimetype,
            imageBase64
        })
    });

    if (!response.ok) {
        throw new Error('Image moderation service failed');
    }

    const result = await response.json();
    if (result.safe === false || result.nudity === true || result.sexual === true) {
        return { safe: false, message: 'This image appears to contain sexual or nude content. Please choose another recipe photo.' };
    }
    return { safe: true };
}

function channelLevelFor(followerCount) {
    let level = 1;
    if (followerCount >= 500) level += 1;
    if (followerCount >= 1000) level += 1;
    if (followerCount >= 2000) level += 1;
    return level;
}

function nextLevelFollowerGoal(followerCount) {
    if (followerCount < 500) return 500;
    if (followerCount < 1000) return 1000;
    if (followerCount < 2000) return 2000;
    return null;
}

async function channelStatsResponse(channelUsername, currentUsername) {
    const followerCount = await Follow.countDocuments({ channelUsername });
    const existingFollow = currentUsername
        ? await Follow.exists({ followerUsername: currentUsername, channelUsername })
        : null;
    const isFollowing = Boolean(existingFollow);

    return {
        channelUsername,
        followerCount,
        level: channelLevelFor(followerCount),
        nextLevelFollowerGoal: nextLevelFollowerGoal(followerCount),
        isFollowing
    };
}

// --- MULTER SETUP ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, path.join(__dirname, 'public', 'uploads')),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'))
});
const upload = multer({ storage });

// --- ROUTES ---

app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword, isAdmin: isAdminEmail(email) });
        await newUser.save();
        res.status(200).json({ success: true });
    } catch (error) { res.status(500).json({ success: false }); }
});

app.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ $or: [{ email: req.body.email }, { username: req.body.username }] });
        if (user && await bcrypt.compare(req.body.password, user.password)) {
            const admin = user.isAdmin || isAdminEmail(user.email);
            if (admin && !user.isAdmin) {
                user.isAdmin = true;
                await user.save();
            }
            req.session.userId = user._id;
            res.json({ success: true, username: user.username, email: user.email, isAdmin: admin });
        } else {
            res.status(401).json({ success: false });
        }
    } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/change-password', async (req, res) => {
    try {
        const { username, newPassword } = req.body || {};
        if (!username || !newPassword || newPassword.length < 6) {
            return res.status(400).json({ success: false, message: 'Enter a password with at least 6 characters.' });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
        res.json({ success: true, message: 'Password updated successfully.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

app.post('/forgot-password/request-otp', async (req, res) => {
    try {
        const email = normalizeEmail(req.body && req.body.email);
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required.' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: 'No account found with this email.' });
        }

        const otp = generateOtp();
        user.resetOtpHash = await bcrypt.hash(otp, 10);
        user.resetOtpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
        await user.save();

        await deliverOtpEmail(user.email, otp);
        res.json({
            success: true,
            message: 'OTP sent to your email.'
        });
    } catch (error) {
        console.error('Forgot password OTP email error:', error);
        res.status(500).json({ success: false, message: 'Could not send OTP email. Please try again later.' });
    }
});

app.post('/forgot-password/reset', async (req, res) => {
    try {
        const email = normalizeEmail(req.body && req.body.email);
        const { otp, newPassword } = req.body || {};
        if (!email || !otp || !newPassword || newPassword.length < 6) {
            return res.status(400).json({ success: false, message: 'Email, OTP, and a 6 character password are required.' });
        }

        const user = await User.findOne({ email });
        if (!user || !user.resetOtpHash || !user.resetOtpExpiresAt || user.resetOtpExpiresAt < new Date()) {
            return res.status(400).json({ success: false, message: 'OTP is invalid or expired.' });
        }

        const validOtp = await bcrypt.compare(otp, user.resetOtpHash);
        if (!validOtp) {
            return res.status(400).json({ success: false, message: 'OTP is invalid or expired.' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.resetOtpHash = undefined;
        user.resetOtpExpiresAt = undefined;
        await user.save();
        res.json({ success: true, message: 'Password reset successfully. Please login.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

app.get('/api/recipes', async (req, res) => {
    try {
        const recipes = await Recipe.find().sort({ createdAt: -1 });
        res.json(recipes.map(recipe => recipeResponse(recipe, req.query.username)));
    } catch (err) { res.status(500).send(err); }
});

app.get('/api/recipes/user', async (req, res) => {
    try {
        const { username } = req.query;
        const recipes = await Recipe.find({ username: username }).sort({ createdAt: -1 });
        res.json(recipes.map(recipe => recipeResponse(recipe, username)));
    } catch (err) { res.status(500).send(err); }
});

app.get('/api/recipes/:id', async (req, res) => {
    try {
        const recipe = await Recipe.findById(req.params.id);
        if (!recipe) return res.status(404).json({ message: 'Recipe not found' });
        res.json(recipeResponse(recipe, req.query.username));
    } catch (err) { res.status(500).send(err); }
});

app.get('/api/channels/updates', async (req, res) => {
    try {
        const { username } = req.query;
        if (!username) return res.status(400).json({ message: 'Username is required' });

        const follows = await Follow.find({ followerUsername: username }).select('channelUsername createdAt');
        const followedRecipeFilters = follows.map(follow => ({
            username: follow.channelUsername,
            createdAt: { $gt: follow.createdAt || new Date(0) }
        }));
        if (followedRecipeFilters.length === 0) {
            return res.json([]);
        }

        const recipes = await Recipe.find({ $or: followedRecipeFilters })
            .sort({ createdAt: -1 })
            .limit(50);
        res.json(recipes.map(recipe => recipeResponse(recipe, username)));
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.get('/api/users/:username/following', async (req, res) => {
    try {
        const follows = await Follow.find({ followerUsername: req.params.username }).sort({ createdAt: -1 });
        const channels = await Promise.all(follows.map(async follow => {
            const recipeCount = await Recipe.countDocuments({ username: follow.channelUsername });
            const followerCount = await Follow.countDocuments({ channelUsername: follow.channelUsername });
            return {
                username: follow.channelUsername,
                recipeCount,
                followerCount,
                followedAt: follow.createdAt
            };
        }));
        res.json(channels);
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.get('/api/channels/:channelUsername/stats', async (req, res) => {
    try {
        res.json(await channelStatsResponse(req.params.channelUsername, req.query.username));
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.get('/api/channels/:channelUsername/followers', async (req, res) => {
    try {
        const followers = await Follow.find({ channelUsername: req.params.channelUsername })
            .select('followerUsername createdAt')
            .sort({ createdAt: -1 });
        res.json(followers.map(follow => ({
            username: follow.followerUsername,
            followedAt: follow.createdAt
        })));
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.post('/api/channels/:channelUsername/follow', async (req, res) => {
    try {
        const followerUsername = req.query.username || (req.body && req.body.username);
        const { channelUsername } = req.params;
        if (!followerUsername) return res.status(400).json({ message: 'Username is required' });
        if (followerUsername === channelUsername) {
            return res.json(await channelStatsResponse(channelUsername, followerUsername));
        }

        await Follow.updateOne(
            { followerUsername, channelUsername },
            { $setOnInsert: { followerUsername, channelUsername } },
            { upsert: true }
        );
        res.json(await channelStatsResponse(channelUsername, followerUsername));
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.delete('/api/channels/:channelUsername/follow', async (req, res) => {
    try {
        const followerUsername = req.query.username || (req.body && req.body.username);
        const { channelUsername } = req.params;
        if (!followerUsername) return res.status(400).json({ message: 'Username is required' });

        await Follow.deleteOne({ followerUsername, channelUsername });
        res.json(await channelStatsResponse(channelUsername, followerUsername));
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.post('/api/recipes', upload.single('imageFile'), async (req, res) => {
    try {
        const { name, description, ingredients, instructions, category, username } = req.body;
        const imageSafety = await isImageSafe(req.file);
        if (!imageSafety.safe) return res.status(400).json({ message: imageSafety.message });
        const youtubeUrl = normalizeYoutubeUrl(req.body.youtubeUrl);
        if (youtubeUrl === null) return res.status(400).json({ message: 'Please enter a valid YouTube link.' });

        const host = req.get('host');
        const imageUrl = req.file ? `${req.protocol}://${host}/uploads/${req.file.filename}` : null;

        const newRecipe = new Recipe({
            title: name,
            description,
            ingredients,
            instructions,
            category,
            username: username || 'anonymous',
            imageUrl,
            youtubeUrl
        });

        await newRecipe.save();
        res.status(201).json(newRecipe);
    } catch (error) {
        console.error("Add Recipe Error:", error);
        res.status(500).send('Server Error');
    }
});

app.put('/api/recipes/:id', upload.single('imageFile'), async (req, res) => {
    try {
        const recipe = await Recipe.findById(req.params.id);
        if (!recipe) return res.status(404).json({ message: 'Recipe not found' });
        const username = req.body.username || req.query.username;
        if (!await canManageRecipe(recipe, username)) {
            return res.status(403).json({ message: 'You can edit only your own recipes.' });
        }

        const { name, description, ingredients, instructions, category } = req.body;
        const imageSafety = await isImageSafe(req.file);
        if (!imageSafety.safe) return res.status(400).json({ message: imageSafety.message });
        const youtubeUrl = normalizeYoutubeUrl(req.body.youtubeUrl);
        if (youtubeUrl === null) return res.status(400).json({ message: 'Please enter a valid YouTube link.' });

        const updateData = {
            title: name,
            description,
            ingredients,
            instructions,
            category,
            youtubeUrl
        };
        if (req.file) {
            const host = req.get('host');
            updateData.imageUrl = `${req.protocol}://${host}/uploads/${req.file.filename}`;
        }
        const updatedRecipe = await Recipe.findByIdAndUpdate(req.params.id, updateData, { new: true });
        res.json(updatedRecipe);
    } catch (error) { res.status(500).send('Server Error'); }
});

app.delete('/api/recipes/:id', async (req, res) => {
    try {
        const recipe = await Recipe.findById(req.params.id);
        if (!recipe) return res.status(404).json({ message: 'Recipe not found' });
        if (!await canManageRecipe(recipe, req.query.username)) {
            return res.status(403).json({ message: 'You can delete only your own recipes.' });
        }
        await Recipe.findByIdAndDelete(req.params.id);
        res.status(204).send();
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.post('/api/recipes/:id/like', async (req, res) => {
    try {
        const { username } = req.query;
        if (!username) return res.status(400).json({ message: 'Username is required' });

        const recipe = await Recipe.findById(req.params.id);
        if (!recipe) return res.status(404).json({ message: 'Recipe not found' });

        recipe.likes = recipe.likes || [];
        const likeIndex = recipe.likes.indexOf(username);
        if (likeIndex >= 0) {
            recipe.likes.splice(likeIndex, 1);
        } else {
            recipe.likes.push(username);
        }

        await recipe.save();
        res.json(recipeResponse(recipe, username));
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.post('/api/recipes/:id/comment', async (req, res) => {
    try {
        const { username, text } = req.body || {};
        if (!username || !text || !text.trim()) {
            return res.status(400).json({ message: 'Username and comment text are required' });
        }

        const recipe = await Recipe.findById(req.params.id);
        if (!recipe) return res.status(404).json({ message: 'Recipe not found' });

        recipe.comments = recipe.comments || [];
        recipe.comments.push({
            username,
            text: text.trim(),
            createdAt: new Date()
        });

        await recipe.save();
        res.json(recipeResponse(recipe, username));
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.delete('/api/recipes/:id/comment/:commentId', async (req, res) => {
    try {
        const { username } = req.query;
        if (!username) return res.status(400).json({ message: 'Username is required' });

        const recipe = await Recipe.findById(req.params.id);
        if (!recipe) return res.status(404).json({ message: 'Recipe not found' });

        const comment = recipe.comments.id(req.params.commentId);
        if (!comment) return res.status(404).json({ message: 'Comment not found' });
        if (comment.username !== username) {
            return res.status(403).json({ message: 'You can delete only your own comment' });
        }

        recipe.comments.pull({ _id: req.params.commentId });
        await recipe.save();
        res.json(recipeResponse(recipe, username));
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.post('/api/recipes/:id/rate', async (req, res) => {
    try {
        const ratingValue = Number(req.query.rating);
        const username = req.query.username || (req.body && req.body.username) || 'anonymous';

        if (!ratingValue || ratingValue < 1 || ratingValue > 5) {
            return res.status(400).json({ message: 'Rating must be between 1 and 5' });
        }

        const recipe = await Recipe.findById(req.params.id);
        if (!recipe) return res.status(404).json({ message: 'Recipe not found' });

        recipe.ratings = recipe.ratings || [];
        const existingRating = recipe.ratings.find(rating => rating.username === username);
        if (existingRating) {
            existingRating.value = ratingValue;
        } else {
            recipe.ratings.push({ username, value: ratingValue });
        }

        const total = recipe.ratings.reduce((sum, rating) => sum + rating.value, 0);
        recipe.rating = total / recipe.ratings.length;

        await recipe.save();
        res.json(recipeResponse(recipe, username));
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.delete('/api/recipes/:id/rate', async (req, res) => {
    try {
        const { username } = req.query;
        if (!username) return res.status(400).json({ message: 'Username is required' });

        const recipe = await Recipe.findById(req.params.id);
        if (!recipe) return res.status(404).json({ message: 'Recipe not found' });

        recipe.ratings = (recipe.ratings || []).filter(rating => rating.username !== username);
        if (recipe.ratings.length > 0) {
            const total = recipe.ratings.reduce((sum, rating) => sum + rating.value, 0);
            recipe.rating = total / recipe.ratings.length;
        } else {
            recipe.rating = 0;
        }

        await recipe.save();
        res.json(recipeResponse(recipe, username));
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
