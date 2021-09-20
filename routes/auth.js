const express = require('express');
const router = new express.Router();
const ExpressError = require('../expressError');
const db = require('../db');
const bcrypt = require('bcrypt');
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require('../config');
const jwt = require('jsonwebtoken');

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post('/register', async (req, res, next) => {
  try {
    const { username, password, first_name, last_name } = req.body;
    if (!username || !password) {
      throw new ExpressError('Username and password required', 400)
    }
    // hash pw
    const hashedpw = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    // save to db 
    const results = await db.query(
      `INSERT INTO users (username, password, first_name, last_name)
      VALUES ($1, $2, $3, $4)
      RETURNING first_name, last_name`, [username, password, first_name, last_name]);
    return res.json(results.rows[0]);
  } catch (e) {
    if (e.code === '23505') {
      return next(new ExpressError('Username taken.', 400));
    }
    return next(e)
  }
})

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      throw new ExpressError("Username and password required", 400);
    }
    const results = await db.query(
      `SELECT username, password
      FROM users
      WHERE username = $1`, [username]);
    const user = results.rows[0];
    if (user) {
      if (await bcrypt.compare(password, user.password)) {
        let token = jwt.sign({username}, SECRET_KEY);
        return res.json({ message: 'Logged in!', token })
      }
    } 
    throw new ExpressError("Invalid username/password", 400);
  } catch (e) {
    return next(e);
  }
})



