export const authMe = async (req, res) => {
  try {
    const user = req.user; // lay tu middleware

    return res.status(200).json({
      user,
    });
  } catch (error) {
    console.error("Error when call authMe", error);
    return res.status(500).json({ message: "Error" });
  }
};
