const authService = require('../services/auth.service');

const register = async (req, res) => {
  const result = await authService.register(req.body);
  res.status(201).json({ data: result });
};

const login = async (req, res) => {
  const result = await authService.login(req.body);
  res.status(200).json({ data: result });
};

const logout = async (req, res) => {
  const result = await authService.logout(req.user.id);
  res.status(200).json({ data: result });
};

const me = async (req, res) => {
  res.status(200).json({ data: authService.getCurrentUser(req.user) });
};

const forgotPassword = async (req, res) => {
  const result = await authService.forgotPassword(req.body);
  res.status(200).json({ data: result });
};

const resetPassword = async (req, res) => {
  const result = await authService.resetPassword(req.body);
  res.status(200).json({ data: result });
};


const updateProfile = async (req, res) => {
  const result = await authService.updateProfile(req.user.id, req.body);
  res.status(200).json({ data: result });
};

module.exports = { register, login, logout, me, forgotPassword, resetPassword, updateProfile };
