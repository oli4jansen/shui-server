"use strict";

// Alle modules importeren
var config          = require("./config");

var _               = require("underscore");
var crypto          = require("crypto");
var emailjs         = require("emailjs/email");

var mysql           = require("mysql");
var orm             = require("orm");

var restify         = require("restify");
var restifyOAuth2   = require("restify-oauth2");

// Restify server instellen
var server = restify.createServer({
    name: "Shui Server",
    version: require("./package.json").version
});

// Middleware

server.use(restify.authorizationParser());
server.use(restify.bodyParser({ mapParams: false }));

server.use(restify.fullResponse());

server.use(restify.CORS({ origins: ['*'] }));
restify.CORS.ALLOW_HEADERS.push('authorization');

var mailServer  = emailjs.server.connect({
    user:     config.smtp.user, 
    password: config.smtp.password, 
    host:     config.smtp.host, 
    ssl:      config.smtp.ssl
});

// Verbinden met MySQL database
orm.connect(config.dbPath, function (err, db) {
    if (err) console.log(err);

    db.load("./models", function (err) {

        if(err) console.log(err);

        var User    = db.models.users;
        var Token   = db.models.tokens;
        var Project = db.models.projects;
        var Task    = db.models.tasks;
        var Message = db.models.messages;

        Project.hasMany('participants', User, { joined: Date }, { reverse: 'projects' });
        Task.hasOne('project', Project, { reverse: 'tasks' });
        Message.hasOne('project', Project, { reverse: 'messages' });

        db.sync();

        /*
            OAuth Hooks
        */

        var hooks = {};

        function generateToken(data) {
            var random = Math.floor(Math.random() * 100001);
            var timestamp = (new Date()).getTime();
            var sha256 = crypto.createHmac("sha256", random + "suchsalt" + timestamp);

            return sha256.update(data).digest("base64");
        }

        hooks.validateClient = function (credentials, req, cb) {
            // Call back with `true` to signal that the client is valid, and `false` otherwise.
            // Call back with an error if you encounter an internal server error situation while trying to validate.

            var isValid = _.has(config.clients, credentials.clientId) && config.clients[credentials.clientId].secret === credentials.clientSecret;
            cb(null, isValid);
        };

        // Functie die aangesproken wordt als de gebruiker geen access token heeft en inlogt met emailadress +
        hooks.grantUserToken = function (credentials, req, cb) {
            // Gebruiker met opgegeven emailadres opzoeken
            User.find({ email: credentials.username }, function(err, data) {

                if(err) console.log(err);

                // Als dit emailadres niks oplevert:
                if(data.length === 0) {
                    var timestamp = (new Date()).getTime();
                    // Generate verification code
                    var code = crypto.createHash('sha1').update(credentials.username+timestamp).digest("hex");

                    // Create new username
                    User.create([{
                        verification_code: code,
                        name: '',
                        email: credentials.username,
                        password: credentials.password
                    }], function(err, data){

                        if(err) console.log(err);

                        var message = {
                           text:    "Please navigate to "+config.clients.webClient.clientPath+"/verification/"+credentials.username+"/"+code, 
                           from:    "Olivier Jansen <oli4jansen.nl@gmail.com>", 
                           to:      credentials.username,
                           subject: "Shui - Confirm email address",
                           attachment: 
                           [
                              {data:"<html>Please navigate to <a href=\""+config.clients.webClient.clientPath+"/verification/"+credentials.username+"/"+code+"\">"+config.clients.webClient.clientPath+"/verification/"+credentials.username+"/"+code+"</a> to confirm your email address.</html>", alternative:true}
                           ]
                        };

                        mailServer.send(message, function(err, message) {
                            if(err) console.log(err);

                            // Token aanmaken
                            var token = generateToken(credentials.username + ":" + credentials.password);                       
                            // Token opslaan in database
                            Token.create([{
                                token: token,
                                email: credentials.username
                            }], function(err, data){
                                if(err) console.log(err);
                                // Token terugsturen naar client
                                return cb(null, token);
                            });
                        });
                    });
                } else if(data.length === 1) {
                    // Wachtwoord controleren
                    if(data[0].password === credentials.password) {
                        // Token aanmaken
                        var token = generateToken(credentials.username + ":" + credentials.password);
                        // Token opslaan in database
                        Token.create([{
                            token: token,
                            email: credentials.username
                        }], function(err, data){
                            // Token terugsturen naar client
                            return cb(null, token);
                        });

                    }else{
                        console.log(data[0].password + '!==' + credentials.password);
                        return cb(null, false);
                    }
                } else {
                    return cb(null, false);
                }
            });
        };

        hooks.authenticateToken = function (token, req, cb) {
            Token.find({ token: token }, function(err, data) {
                if(err) {
                    return cb(null, false);
                }else{
                    req.username = data[0].email;
                    return cb(null, true);
                }
            });
        };

        restifyOAuth2.ropc(server, { tokenEndpoint: '/token', hooks: hooks });

        /*
            API routes and response functions
        */

    // Get user details
        server.get('/me', function (req, res) {
            if (!req.username) return res.sendUnauthenticated();
            console.log('/me');
            res.contentType = "application/json";

            User.get(req.username, function (err, me) {

                if(err) console.log(err);

                if(me) {

                    console.log(me.verification_code);

                    if(me.verification_code == '') {
                        var verified = true;
                    }else{
                        var verified = false;
                    }

                    res.send({
                        verified: verified,
                        name: me.name,
                        email: me.email,
                        emailNotifications: me.email_notifications,
                        mobileNotifications: me.mobile_notifications
                    });
                }else{
                    res.status(404);
                    res.send({})
                }
            });
        });

    // Update user details
        server.post('/me', function (req, res) {
            if (!req.username) return res.sendUnauthenticated();
            console.log('/me [POST]');
            res.contentType = "application/json";

            if(req.body.name !== undefined && req.body.name !== '') {
                User.get(req.username, function (err, me) {

                    me.name = req.body.name;
                    me.save(function (err) {
                        if(err) {
                            console.log(err);
                            res.status(500);
                            res.send({ msg: 'Something went wrong while updating your settings.' });
                        }else{
                            res.send({
                                name: me.name,
                                email: me.email,
                                emailNotifications: me.email_notifications,
                                mobileNotifications: me.mobile_notifications
                            });
                        }
                    });
                });
            }else{
                res.status(500);
                res.send({ msg: 'You didnt provide any information to update.' });
            }
        });

    // Check email address verification code
        server.post('/verify', function (req, res) {
            console.log('/verify');
            res.contentType = "application/json";

            if(req.body.email !== undefined && req.body.code !== '') {
                User.get(req.body.email, function (err, me) {

                    if(!err && req.body.code === me.verification_code) {
                        me.verification_code = '';
                        me.save(function (err) {
                            if(err) {
                                console.log(err);
                                res.status(500);
                                res.send({ msg: 'Your code matched but we couldnt update our database.' });
                            }else{
                                res.send({});
                            }
                        });
                    }else if(me.verification_code == '') {
                        res.status(200);
                        res.send({ msg: 'Account is already verified.' });
                    }else{
                        res.status(401);
                        res.send({ msg: 'Your code didnt match ours.' });                        
                    }
                });
            }
        });

    // Get all projects
        server.get('/projects', function (req, res) {
            if (!req.username) return res.sendUnauthenticated();
            console.log('/projects');
            res.contentType = "application/json";

            User.get(req.username, function (err, me) {
                me.getProjects(function (err, projects) {

                    projects.forEach(function (project) {

                        project.openTasks = 0;
                        project.myTasks = 0;
                        project.participants = [];

                        project.getTasks(function (err, tasks) {
                            if(tasks) {
                                tasks.forEach(function (task) {
                                    if(!task.finished) project.openTasks++;
                                    if(!task.finished && task.assignedTo == req.username) project.myTasks++;
                                });
                            }

                            project.getParticipants(function (err, participants) {
                                participants.forEach(function (participant) {
                                    project.participants.push({ name: participant.name, email: participant.email });
                                });

                                res.send(projects);
                            });
                        });
                    });
                });
            });
        });

    // Get project details
        server.get('/projects/:id', function (req, res) {
            if (!req.username) return res.sendUnauthenticated();
            console.log('/projects/:id');
            res.contentType = "application/json";

            Project.get(req.params.id, function (err, project) {
                project.getParticipants(function (err, participants) {
                    User.get(req.username, function (err, me) {
                        project.hasParticipants(me, function (err, bool) {
                            if(bool) {
                                project.getTasks(function (err, tasks) {
                                    var response = project;

                                    response.myTasks = 0;

                                    if(tasks) {
                                        tasks.forEach(function (task) {
                                            if(!task.finished && task.assignedTo == req.username) response.myTasks++;
                                        });
                                    }

                                    response.participants = [];
                                    participants.forEach(function(participant) {
                                        response.participants.push({
                                            name: participant.name,
                                            email: participant.email
                                        });
                                    });
                                    response.tasks = (tasks) ? tasks.length : 0;
                                    response.messages = 2;
                                    response.files = 1;

                                    res.send(response);
                                });
                            }else{
                                res.status(404);
                                res.send({ msg: 'User does not have a project with that ID.' });
                            }
                        });
                    });
                });
            });
        });

    // Get all tasks
       server.get('/projects/:id/tasks', function (req, res) {
            if (!req.username) return res.sendUnauthenticated();
            console.log('/projects/:id/tasks');
            res.contentType = "application/json";

            Project.get(req.params.id, function (err, project) {
                project.getParticipants(function (err, participants) {
                    User.get(req.username, function (err, me) {
                        project.hasParticipants(me, function (err, bool) {
                            if(bool) {
                                project.getTasks(function (err, tasks) {
                                    if(err) console.log(err);
                                    if(tasks) {
                                        res.send(tasks);
                                    }else{
                                        res.send([]);
                                    }
                                });
                            }else{
                                res.status(404);
                                res.send({ msg: 'User does not have a project with that ID.' });
                            }
                        });
                    });
                });
            });
        });

    // Create a task
       server.post('/projects/:id/tasks', function (req, res) {
            if (!req.username) return res.sendUnauthenticated();
            console.log('/projects/:id/tasks [POST]');
            res.contentType = "application/json";

            Project.get(req.params.id, function (err, project) {
                project.getParticipants(function (err, participants) {
                    User.get(req.username, function (err, me) {
                        project.hasParticipants(me, function (err, bool) {
                            if(bool) {

                                Task.create({
                                    project_id  : req.params.id,
                                    name        : req.body.name,
                                    description : req.body.description,
                                    assignedBy  : req.username,
                                    assignedTo  : req.body.assignedTo,
                                    finished    : false,
                                    hours       : 0
                                }, function (err, item) {
                                    if(err) {
                                        console.log(err);
                                        res.status(500);
                                        res.send({ msg: err });
                                    }else{
                                        res.send(item);

                                        // Trigger notification HERE (to person task is assigned to)
                                    }
                                });
                            }else{
                                res.status(404);
                                res.send({ msg: 'User does not have a project with that ID.' });
                            }
                        });
                    });
                });
            });
        });

    // Delete a task
        server.del('/projects/:id/tasks/:taskId', function (req, res) {
            if (!req.username) return res.sendUnauthenticated();
            console.log('/projects/:id/tasks/:taskId [DELETE]');
            res.contentType = "application/json";

            Project.get(req.params.id, function (err, project) {
                project.getParticipants(function (err, participants) {
                    User.get(req.username, function (err, me) {
                        project.hasParticipants(me, function (err, bool) {
                            if(bool) {
                                Task.get(req.params.taskId, function (err, task) {
                                    if(task.assignedBy == req.username) {
                                        task.remove(function (err) {
                                            if(err) {
                                                console.log(err);
                                                res.status(500);
                                                res.send({ msg: err });
                                            }else{
                                                res.send({});
                                            }
                                        });
                                    }else{
                                        res.status(401);
                                        res.send({ msg: 'Unauthorized, this task wasnt created by you.' });
                                    }
                                });
                            }else{
                                res.status(404);
                                res.send({ msg: 'User does not have a project with that ID.' });
                            }
                        });
                    });
                });
            });
        });

    // Finish a task
        server.post('/projects/:id/tasks/:taskId', function (req, res) {
            if (!req.username) return res.sendUnauthenticated();
            console.log('/projects/:id/tasks/:taskId [POST]');
            res.contentType = "application/json";

            Project.get(req.params.id, function (err, project) {
                project.getParticipants(function (err, participants) {
                    User.get(req.username, function (err, me) {
                        project.hasParticipants(me, function (err, bool) {
                            if(bool) {
                                Task.get(req.params.taskId, function (err, task) {
                                    if(task.assignedTo == req.username) {
                                        task.hours = parseFloat(req.body.hours);
                                        task.finished = true;
                                        task.evaluation = req.body.evaluation;

                                        task.save(function (err) {
                                            if(err) {
                                                console.log(err);
                                                res.status(500);
                                                res.send({ msg: err });
                                            }else{
                                                res.send({});

                                                // Trigger notification HERE (to person that assigned task)

                                            }
                                        });
                                    }else{
                                        res.status(401);
                                        res.send({ msg: 'Unauthorized, this task wasnt assigned to you.' });
                                    }
                                });
                            }else{
                                res.status(404);
                                res.send({ msg: 'User does not have a project with that ID.' });
                            }
                        });
                    });
                });
            });
        });

    // Get all messages
       server.get('/projects/:id/messages', function (req, res) {
            if (!req.username) return res.sendUnauthenticated();
            console.log('/projects/:id/messages');
            res.contentType = "application/json";

            Project.get(req.params.id, function (err, project) {
                project.getParticipants(function (err, participants) {
                    User.get(req.username, function (err, me) {
                        project.hasParticipants(me, function (err, bool) {
                            if(bool) {
                                project.getMessages([ "id", "Z"], function (err, messages) {
                                    if(err) console.log(err);
                                    if(messages) {
                                        res.send(messages);
                                    }else{
                                        res.send([]);
                                    }
                                });
                            }else{
                                res.status(404);
                                res.send({ msg: 'User does not have a project with that ID.' });
                            }
                        });
                    });
                });
            });
        });

    // Create a message
       server.post('/projects/:id/messages', function (req, res) {
            if (!req.username) return res.sendUnauthenticated();
            console.log('/projects/:id/messages [POST]');
            res.contentType = "application/json";

            Project.get(req.params.id, function (err, project) {
                project.getParticipants(function (err, participants) {
                    User.get(req.username, function (err, me) {
                        project.hasParticipants(me, function (err, bool) {
                            if(bool) {

                                var now = new Date();
                                var year = now.getFullYear();
                                var month = now.getMonth()+1;
                                var date = now.getDate();
                                var hours = now.getHours();
                                var minutes = now.getMinutes();
                                var seconds = now.getSeconds();

                                Message.create({
                                    body       : req.body.body,
                                    author     : req.username,
                                    project_id : req.params.id,
                                    created    :  year+'-'+month+'-'+date+' '+hours+':'+minutes+':'+seconds
                                }, function (err, item) {
                                    if(err) {
                                        console.log(err);
                                        res.status(500);
                                        res.send({ msg: err });
                                    }else{
                                        res.send(item);

                                        // Trigger notification HERE (to person task is assigned to)
                                    }
                                });
                            }else{
                                res.status(404);
                                res.send({ msg: 'User does not have a project with that ID.' });
                            }
                        });
                    });
                });
            });
        });
        server.listen(3000);
    });
});
