const express = require('express');
const app = express();
const mysql = require('mysql');
const bodyparser = require('body-parser');
app.use(bodyparser.json());
app.use(bodyparser.urlencoded({ extended: true }));
const dbConfig = require("./config.js");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
app.use(express.static("public"))

const connection = mysql.createConnection({
  host: dbConfig.HOST,
  user: dbConfig.USER,
  password: dbConfig.PASSWORD,
  database: dbConfig.DB
});


// open the MySQL connection
connection.connect(error => {
  if (error) throw error;
  console.log("Successfully connected to the database.");
});

// user register
app.post('/register', async (req, res) => {
  const hashPassword = await bcrypt.hash(req.body.password,10)
  let values = [];
  values.push([
    req.body.username,
    hashPassword,
    req.body.email,
    req.body.address
  ]);
  let que = `insert into userlogin(username, password, email, address) values ? `;
  connection.query(que, [values], (err, result) => {
    if (err) throw err;
    res.status(201).send(`"message": "new user created"`);
  });
});

// user login
app.post('/login', async (req, res) =>{
  let values = [];
  values.push([
    req.body.username,
    req.body.Password
  ]);
  connection.query("select * from userlogin where username = ?", [req.body.username], (err, result) => {
    if (err) throw err;
    // check if the user is available in db
    if(result.length > 0){
      if(bcrypt.compareSync(req.body.password, result[0].password)){
        jwt.sign({user:result}, 'secretKey', (err, accessToken) =>{
          res.status(200).send({
            "message":"success",
            accessToken
          });
        })
      }else{
        res.sendStatus(403);
      }
    }else{
      res.sendStatus(403);
    }
    
    
  });

})

// post articles
app.post('/articles', verifyToken , (req, res) => {
  let values = [];
  values.push([
    req.body.title,
    req.body.body,
    req.body.author
  ]);
  let que = `insert into articles(title, body, author) values ? `;
  connection.query(que, [values], (err, result) => {
    if (err) throw err;
    res.status(201).send(`"message": "new article created"`);
  });
});

// get all articles
app.get('/articles', (req, res) => {
  connection.query(`SELECT * FROM articles ORDER BY  id DESC`, (err, result) => {
    if (err) throw err;
    res.send(result);
  });
});


// verify token 
function verifyToken(req, res, next){
  const header = req.headers['authorization'];

  if(typeof header !== 'undefined') {
      const bearer = header.split(' ');
      const token = bearer[1];

      req.token = token;
      next();
  } else {
      res.sendStatus(403)
  }
}

const port = process.env.PORT||8000;
const server = app.listen(port, function () {
  console.log(`listening to the port ${port}`);
});

module.exports = connection;
