const express = require('express')
const dotenv = require('dotenv')
const { MongoClient } = require('mongodb'); 
const bodyparser = require('body-parser')
const cors = require('cors')
const CryptoJS = require('crypto-js');

dotenv.config()

// Setup MongoDB Client without calling global connect
const url = process.env.MONGO_URI;
const client = new MongoClient(url);

// A clean helper function that safely connects only when a request comes in
async function getConnectedDb() {
    if (!client.topology || !client.topology.isConnected()) {
        await client.connect();
    }
    return client.db(process.env.DB_NAME);
}

const app = express()
const port = 3000 

// Middleware
app.use(bodyparser.json())
app.use(cors())

// Get all the passwords with decryption (Updated path to /api)
app.get('/api', async (req, res) => {
    try {
        const db = await getConnectedDb(); // Handled safely inside the route
        const collection = db.collection('passwords');
        const findResult = await collection.find({ adminEmail: req.query.adminEmail }).toArray();

        // Loop through each password document and decrypt it
        const decryptedPasswords = findResult.map(item => {
            if (item.password) {
                try {
                    const bytes = CryptoJS.AES.decrypt(item.password, process.env.SECRET_KEY);
                    const decryptedText = bytes.toString(CryptoJS.enc.Utf8);
                    
                    if (decryptedText) {
                        item.password = decryptedText; // Replace hash with plain text
                    }
                } catch (err) {
                    console.log(`Skipping decryption for entry: ${item.website || 'unknown'}`);
                }
            }
            return item;
        });

        res.json(decryptedPasswords);
    } catch (error) {
        console.error("Error fetching passwords:", error);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});

// Get all the admins with decrypted passwords (Updated path to /api/GetAdmins)
app.get('/api/GetAdmins', async (req, res) => {
    try {
        const db = await getConnectedDb();
        const collection = db.collection('admins');
        const findResult = await collection.find({}).toArray();

        // Loop through each admin and decrypt their password
        const decryptedAdmins = findResult.map(admin => {
            if (admin.admin_password) {
                const bytes = CryptoJS.AES.decrypt(admin.admin_password, process.env.SECRET_KEY);
                admin.admin_password = bytes.toString(CryptoJS.enc.Utf8);
            }
            return admin;
        });

        res.json(decryptedAdmins);
    } catch (error) {
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// Save a password with AES encryption (Updated path to /api)
app.post('/api', async (req, res) => { 
    try {
        const passwordData = req.body;
        const db = await getConnectedDb();
        const collection = db.collection('passwords');

        // Encrypt the specific website password field using your SECRET_KEY
        if (passwordData.password) {
            const encryptedPassword = CryptoJS.AES.encrypt(passwordData.password, process.env.SECRET_KEY).toString();
            passwordData.password = encryptedPassword; // Overwrite plain text with encrypted text
        }

        const findResult = await collection.insertOne(passwordData);
        res.send({ success: true, result: findResult });
    } catch (error) {
        console.error("Error saving password:", error);
        res.status(500).send({ success: false, message: "Server error" });
    }
});

// Register admin with AES (Updated path to /api/registeradmin)
app.post('/api/registeradmin', async (req, res) => { 
    try {
        const adminData = req.body;
        const db = await getConnectedDb();
        const collection = db.collection('admins');

        // 1. Encrypt the password using your Secret Key
        const encryptedPassword = CryptoJS.AES.encrypt(adminData.admin_password, process.env.SECRET_KEY).toString();

        // 2. Overwrite the plain password with the cipher text
        adminData.admin_password = encryptedPassword;

        const findResult = await collection.insertOne(adminData);
        res.send({ success: true, result: findResult });
    } catch (error) {
        res.status(500).send({ success: false, message: "Server error" });
    }
});

// Delete a password by id (Updated path to /api)
app.delete('/api', async (req, res) => { 
    try {
        const db = await getConnectedDb();
        const collection = db.collection('passwords');
        
        // Explicitly target your custom uuid field 'id'
        const findResult = await collection.deleteOne({ id: req.body.id });
        
        res.send({ success: true, result: findResult })
    } catch (error) {
        res.status(500).send({ success: false, message: "Server error" });
    }
})

// Update a password by custom id (Updated path to /api)
app.put('/api', async (req, res) => {
    try {
        const db = await getConnectedDb();
        const collection = db.collection('passwords');
        
        // Extract the custom id from the body
        const { id, website, username, password } = req.body;
        
        // Explicitly target your custom uuid field 'id'
        const findResult = await collection.updateOne(
            { id: id }, 
            { $set: { website, username, password } } // Updates only these fields
        );
        
        res.send({ success: true, result: findResult });
    } catch (error) {
        res.status(500).send({ success: false, message: "Server error" });
    }
});

// Local development server configuration
if (process.env.NODE_ENV !== 'production') {
    app.listen(port, () => {
        console.log(`Local app listening on  http://localhost:${port}`)
    })
}

// Export module cleanly for Vercel Serverless environment
module.exports = app;
