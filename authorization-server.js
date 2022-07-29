const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get("/authorize", (req, res) => {
	const { clientId } = req.query
	const client = clients[clientId]
	if (!client) {
		res.status(401).send("Invalid client")
		return
	} else {
		res.status(200).end()
	}
	if (!containsAll(client.scopes, req.query.scope)) {
		res.status(401).send("Invalid scope")
		return
	}
	state = randomString()
	res.render("login", { clientId, state, scopes: req.query.scope })

})

app.post("/approve", (req, res) => {
	const { userName, password, requestId } = req.body
	const request = requests[requestId]
	if (!request) {
		res.status(401).send("Invalid request")
		return
	}
	if (userName !== request.userName || password !== users[request.userName]) {
		res.status(401).send("Invalid credentials")
		return
	}
	const code = randomString()
	authorizationCodes[code] = {
		clientReq: request.clientReq,
		userName: request.userName,
	}
	res.redirect(`${request.redirectUri}?code=${code}`)
})

app.post("/token", (req, res) => {
	const { grant_type, code, redirect_uri } = req.body
	if (grant_type !== "authorization_code") {
		res.status(400).send("Invalid grant_type")
		return
	}
	const authCode = authorizationCodes[code]
	if (!authCode) {
		res.status(400).send("Invalid code")
		return
	}
	if (redirect_uri !== authCode.clientReq.redirectUri) {
		res.status(400).send("Invalid redirect_uri")
		return
	}
	const accessToken = randomString()
	const refreshToken = randomString()
	const token = {
		accessToken,
		refreshToken,
		expiresIn: 3600,
		tokenType: "Bearer",
		scope: authCode.clientReq.scope,
	}
	res.json(token)
})





const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
