var orm             = require("orm");

module.exports = function (db, cb) {

	// User model
    db.define("users", {
        verification_code   : String,
        reset_code          : String,
        name                : String,
        email               : String,
        password            : String,
        salt                : String,
        email_notifications : Boolean,
        mobile_notifications: Boolean
    }, {
	    id   : 'email',
	    validations: {
	    	email: orm.validators.patterns.email("An valid email adress is required.")
	    }
   	});

    // Token model
    db.define('tokens', {
        token     : String,
        created   : Date,
        email     : String
    }, {
	    id   : 'email'
   	});

   	// Project model
   	db.define('projects', {
   		name     : String,
   		deadline : String,
   		created  : String
   	});

   	// Task model
   	db.define('tasks', {
   		name        : String,
   		description : String,
   		assignedBy  : String,
   		assignedTo  : String,
   		finished    : Boolean,
   		evaluation  : String,
   		hours       : String
   	});

   	// Message model
   	db.define('messages', {
   		created     : String,
   		body        : String,
   		author      : String
   	});

   	// Files model
   	db.define('files', {
   		created     : String,
   		name        : String,
   		description : String,
   		url         : String,
   		author      : String
   	});

   	// Notifications model
   	db.define('notifications', {
   		type         : String,
      unread       : Boolean,
      project_id   : Number,
      project_name : String,
   		sender_name  : String
   	});

    return cb();
};