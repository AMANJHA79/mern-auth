const getUserdata = async (req, res) => {
    console.log("Received request to get user data");
    const userId = req.body.userId; // Get userId from the request body
    console.log("User ID:", userId);

    try {
        const user = await User.findById(userId); // Fetch user data from the database
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        return res.status(200).json({
            success: true,
            data: user
        });
    } catch (error) {
        console.error("Error fetching user data:", error); // Log the error
        return res.status(500).json({
            success: false,
            message: 'Server error, please try again!'
        });
    }
};

module.exports = { getUserdata };