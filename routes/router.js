import express from 'express';
const router = express.Router();

import bcrypt from 'bcryptjs';
import uuid  from 'uuid';
import jwt from 'jsonwebtoken';

const db = require('../lib/db.js');
const userMiddleware = require('../middleware/users.js');

router.post('/sign-up', userMiddleware.validateRegister, (req, res, next) => {
  db.query(
    'SELECT id FROM users WHERE LOWER(username) = LOWER(?)',
    [req.body.username],
    (err, result) => {
      if (result && result.length) {
        // error
        return res.status(409).send({
          message: 'This username is already in use!',
        });
      } else {
        // username not in use
        bcrypt.hash(req.body.password, 10, (err, hash) => {
          if (err) {
            return res.status(500).send({
              message: err,
            });
          } else {
            db.query(
              'INSERT INTO users (id, username, password, registered) VALUES (?, ?, ?, now());',
              [uuid.v4(), req.body.username, hash],
              (err, result) => {
                if (err) {
                  return res.status(400).send({
                    message: err,
                  });
                }
                return res.status(201).send({
                  message: 'Registered!',
                });
              }
            );
          }
        });
      }
    }
  );
});

router.post('/login', (req, res, next) => {});

router.get('/secret-route', (req, res, next) => {
  res.send('This is the secret content. Only logged in users can see that!');
});

module.exports = router;