/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const
    bodyParser = require('body-parser'),
    config = require('config'),
    crypto = require('crypto'),
    express = require('express'),
    https = require('https'),
    request = require('request'),
    mongoose = require("mongoose");


var app = express();

mongoose.connect("mongodb://gpereira.tk/bill");
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({verify: verifyRequestSignature}));
app.use(express.static('public'));


var byllSchema = new mongoose.Schema({
    id: Number,
    person: String,
    price: Number
});

var Bill = mongoose.model("Bill", byllSchema);
/*
 * Be sure to setup your config values before running this code. You can
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
    process.env.MESSENGER_APP_SECRET :
    config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
    (process.env.MESSENGER_VALIDATION_TOKEN) :
    config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
    (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
    config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
const SERVER_URL = (process.env.SERVER_URL) ?
    (process.env.SERVER_URL) :
    config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
    console.error("Missing config values");
    process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function (req, res) {
    if (req.query['hub.mode'] === 'subscribe' &&
        req.query['hub.verify_token'] === VALIDATION_TOKEN) {
        console.log("Validating webhook");
        res.status(200).send(req.query['hub.challenge']);
    } else {
        console.error("Failed validation. Make sure the validation tokens match.");
        res.sendStatus(403);
    }
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
    var data = req.body;

    // Make sure this is a page subscription
    if (data.object == 'page') {
        // Iterate over each entry
        // There may be multiple if batched
        data.entry.forEach(function (pageEntry) {
            var pageID = pageEntry.id;
            var timeOfEvent = pageEntry.time;

            // Iterate over each messaging event
            pageEntry.messaging.forEach(function (messagingEvent) {
                if (messagingEvent.optin) {
                    receivedAuthentication(messagingEvent);
                } else if (messagingEvent.message) {
                    receivedMessage(messagingEvent);
                } else if (messagingEvent.delivery) {
                    receivedDeliveryConfirmation(messagingEvent);
                } else if (messagingEvent.postback) {
                    receivedPostback(messagingEvent);
                } else if (messagingEvent.read) {
                    receivedMessageRead(messagingEvent);
                } else if (messagingEvent.account_linking) {
                    receivedAccountLink(messagingEvent);
                } else {
                    console.log("Webhook received unknown messagingEvent: ", messagingEvent);
                }
            });
        });

        // Assume all went well.
        //
        // You must send back a 200, within 20 seconds, to let us know you've
        // successfully received the callback. Otherwise, the request will time out.
        res.sendStatus(200);
    }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL.
 *
 */
app.get('/authorize', function (req, res) {
    var accountLinkingToken = req.query['account_linking_token'];
    var redirectURI = req.query['redirect_uri'];

    // Authorization Code should be generated per user by the developer. This will
    // be passed to the Account Linking callback.
    var authCode = "1234567890";

    // Redirect users to this URI on successful login
    var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

    res.render('authorize', {
        accountLinkingToken: accountLinkingToken,
        redirectURI: redirectURI,
        redirectURISuccess: redirectURISuccess
    });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
    var signature = req.headers["x-hub-signature"];

    if (!signature) {
        // For testing, let's log an error. In production, you should throw an
        // error.
        console.error("Couldn't validate the signature.");
    } else {
        var elements = signature.split('=');
        var method = elements[0];
        var signatureHash = elements[1];

        var expectedHash = crypto.createHmac('sha1', APP_SECRET)
            .update(buf)
            .digest('hex');

        if (signatureHash != expectedHash) {
            throw new Error("Couldn't validate the request signature.");
        }
    }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfAuth = event.timestamp;

    // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
    // The developer can set this to an arbitrary value to associate the
    // authentication callback with the 'Send to Messenger' click event. This is
    // a way to do account linking when the user clicks the 'Send to Messenger'
    // plugin.
    var passThroughParam = event.optin.ref;

    console.log("Received authentication for user %d and page %d with pass " +
        "through param '%s' at %d", senderID, recipientID, passThroughParam,
        timeOfAuth);

    // When an authentication is received, we'll send a message back to the sender
    // to let them know it was successful.
    sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */
function receivedMessage(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfMessage = event.timestamp;
    var message = event.message;

    console.log("Received message for user %d and page %d at %d with message:",
        senderID, recipientID, timeOfMessage);
    console.log(JSON.stringify(message));

    var isEcho = message.is_echo;
    var messageId = message.mid;
    var appId = message.app_id;
    var metadata = message.metadata;

    // You may get a text or attachment but not both
    var messageText = message.text;
    var messageAttachments = message.attachments;
    var quickReply = message.quick_reply;

    if (isEcho) {
        // Just logging message echoes to console
        console.log("Received echo for message %s and app %d with metadata %s",
            messageId, appId, metadata);
        return;
    } else if (quickReply) {
        var quickReplyPayload = quickReply.payload;
        console.log("Quick reply for message %s with payload %s",
            messageId, quickReplyPayload);
        messageText = quickReplyPayload.toString();
        //sendTextMessage(senderID, "Quick reply tapped");
        //return;
    }

    if (messageText) {

        // If we receive a text message, check to see if it matches any special
        // keywords and send back the corresponding example. Otherwise, just echo
        // the text we received.

        var re = /^(.+?)\s(paid|spent)\s(.+?)€/;
        var str = messageText;
        var m;

        if ((m = re.exec(str)) !== null) {
            if (m.index === re.lastIndex) {
                re.lastIndex++;
            }
            // View your result using the m-variable.
            // eg m[0] etc.

            // ADD USER or JUST ADD EXPENSE
            sendTextMessage(senderID, "An expense was added to " + m[1] + " for the value of " + m[3] + "€. To check current status use 'stats'.");

            Bill.findOne({id: senderID, person: m[1]}, function (error, docs) {
                if (error) {
                    // Output to log
                } else if (docs) {

                    if (typeof docs.price == "undefined") {
                        // User doesn't exist
                        // Create user
                        var newUser = {
                            id: senderID,
                            person: m[1],
                            price: Number(m[3])
                        };

                        Bill.create(newUser);
                    } else {
                        // User already exists, update
                        Bill.findOneAndUpdate({
                            id: senderID,
                            person: m[1]
                        }, {price: Number(m[3]) + Number(docs.price)}, function (err, docu) {
                        });
                    }
                } else {
                    var newUser = {
                        id: senderID,
                        person: m[1],
                        price: Number(m[3])
                    };

                    Bill.create(newUser);
                }
            });
            /*
             Bill.findOne({ id: senderID, person: m[1] }, function (error, docs){
             sendTextMessage(senderID, "Current status for " + m[1] + ": " + docs.price + "€");	// IT DOESN'T SHOW THE CURRENT, BUT RATHER THE PREVIOUS STATE
             });
             */
            /*
             Bill.findOne({ id: senderID, person: m[1] }, function (error, docs){
             if (error){
             //Output error
             } else if (docs) {
             if (typeof docs.price == "undefined"){
             sendTextMessage(senderID, "I don't think I know who " + m[1] + " is.");
             } else {
             sendTextMessage(senderID, "Current status for " + m[1] + ": " + docs.price + "€");	// IT DOESN'T SHOW THE CURRENT, BUT RATHER THE PREVIOUS STATE
             }
             }
             });
             */
            /*
             Blog.findByIdAndUpdate(req.params.id, req.body.blog, function (error, blog) {
             if (error) {
             res.redirect("/blogs");
             } else {
             res.redirect("/blogs/" + req.params.id)
             }
             });
             */
            return;
        }


        re = /^(.+?)\s(didn't pay|didn't spend)\s(.+?)€/;
        str = messageText;
        var n;

        if ((n = re.exec(str)) !== null) {
            if (n.index === re.lastIndex) {
                re.lastIndex++;
            }

            Bill.findOne({id: senderID, person: n[1]}, function (error, docs) {
                if (error) {
                    // Output to log
                } else if (docs) {
                    if (typeof docs.price == "undefined") {
                        // User doesn't exist
                        sendTextMessage(senderID, "I don't think I know who " + n[1] + " is.");
                    } else {
                        // User already exists, update
                        if (Number(docs.price) < Number(n[3])) {
                            sendTextMessage(senderID, n[1] + " never paid that much in the first place. Use another value.");
                        } else {
                            Bill.findOneAndUpdate({
                                id: senderID,
                                person: n[1]
                            }, {price: Number(docs.price) - Number(n[3])}, function (err, docu) {
                            });
                            sendTextMessage(senderID, "I'll remove the expense of " + n[1] + ", for the value of " + n[3] + "€. To check current status use 'stats'.");
                        }
                    }
                } else {
                    sendTextMessage(senderID, "I don't think I know who " + n[1] + " is.");
                }
            });
            /*
             Bill.findOne({ id: senderID, person: n[1] }, function (error, docs){
             sendTextMessage(senderID, "Current status for " + n[1] + ": " + docs.price + "€");  // IT DOESN'T SHOW THE CURRENT, BUT RATHER THE PREVIOUS STATE
             });
             */
            /*
             Bill.findOne({ id: senderID, person: n[1] }, function (error, docs){
             if (error){
             //Output error
             } else if (docs) {
             if (typeof docs.price == "undefined"){
             sendTextMessage(senderID, "I don't think I know who " + n[1] + " is.");
             } else {
             sendTextMessage(senderID, "Current status for " + n[1] + ": " + docs.price + "€");	// IT DOESN'T SHOW THE CURRENT, BUT RATHER THE PREVIOUS STATE
             }
             }
             });
             */
            return;
            // Remove expense or give warning
        }


        switch (messageText.toLowerCase()) {
            case "hi":
            case "hi.":
            case "hi...":
            case "hi!":
            case "hello":
            case "hello.":
            case "hello...":
            case "hello!":
            case "hey":
            case "hey!":
            case "good morning":
            case "good morning.":
            case "good morning!":
            case "good evening":
            case "good evening!":
            case "good evening.":
            case "good night":
            case "good night.":
            case "good night!":
                sendQuickYesNo(senderID);
                // sendTextMessage(senderID, "Hi! My name is Byll, I'm here to help you split your bills with your friends... Type 'help' to see the words I understand :)");
                break;

            case "help":
            case "?":
            case "commands":
                sendTextMessage(senderID, "Type 'start' or 'begin' to start a new session. Record everyone's expenses and split the bill at the end. Add your your friends by simply saying 'Mary paid 20€' or even 'Steve spent 0€'... When you're done, just 'split the bill'! ;) ('help2' for more)");
                break;

            case "help2":
            case "?2":
                sendTextMessage(senderID, "Remove someone with (for example) 'Remove Steve' and remove expenses with 'John didn't pay 10€'. Check the current status, and see how much money each user spent so far using 'stats' or 'current'. Delete everything and start over with 'reset' or 'fresh start'.");
                break;

            case "start recording":
            case "start":
            case "begin":
                // START A NEW SENDER ID ON DATABASE
                /*
                 if it already exists:
                 sendTextMessage(senderID, "There's a session running already. Use 'reset' if you want to start over.");
                 */

                sendTextMessage(senderID, "I just started a new session :) Add users, or simply start adding expenses...");
                break;

            case "fresh start":
            case "reset":
                //Similar to start, but removes everything first
                Bill.delete({id: senderID}, function (error) {
                    if (error) {
                        console.log(error);
                    }
                });
                break;

            case "add users":
            case "add user":

                // Procedure to add multiple users at once...
                break;

            case "status":
            case "stats":
            case "current":
            case "db":
                Bill.find({id: senderID}, function (error, results) {
                    if (!error) {
                        results.forEach(function (result) {
                            sendTextMessage(senderID, result.person + " - paid " + result.price + "€ (so far)");
                        });
                    } else {
                        sendTextMessage(senderID, error);
                    }
                });
                break;

            case "split the bill":
            case "results":
                try {
                    Bill.find({}, function (error, results) {
                            sendTextMessage(senderID, results.length);
                            if (!error && results.length > 2) {
                                var sum = 0;
                                var n = 0;
                                results.forEach(function (result) {
                                    sum += result.price;
                                    n++;
                                });
                                if (n != 0) var average = sum / n;
                                for (var i = 0; typeof results[i].price != "undefined" && i < results.length; i++) {
                                    for (var j = 0; typeof results[j].price != "undefined" && j < results.length; j++) {
                                        if (results[i].price > results[j].price) {
                                            var prov = results[j];
                                            results[j] = results[i];
                                            results[i] = prov;
                                        }
                                    }
                                }
                                for (var i = 0; typeof results[i].price != "undefined" && i < results.length; i++) {
                                    results[i].price = results[i].price - average;
                                    results[i].paywho = [];
                                    results[i].payhowmuch = [];
                                }

                                for (var i = 0; i < results.length; i++) {
                                    if (typeof results[i].price != "undefined" && results[i].price != 0 && results[i].price < 0) {
                                        for (var j = i + 1; typeof results[j].price != "undefined" && j < results.length; j++) {
                                            if (typeof results[j].price != "undefined" && typeof results[i].price != "undefined" && Math.abs(results[i].price) < results[j].price && results[j].price > 0) {
                                                var prov = results[j].price;
                                                results[j].price += results[i].price;
                                                results[i].price = 0;
                                                results[i].paywho[1] = results[j].person;
                                                results[i].payhowmuch[1] = prov;
                                            }
                                        }
                                        while (typeof results[i].price != "undefined" && results[i].price < 0) {
                                            var k = 0;
                                            var difpag = Math.abs(results[i].price);
                                            var difrece = results[j].price;
                                            if (difpag > difrece) {
                                                results[j].price += results[i].price;
                                                results[i].price = 0;
                                                results[i].payhowmuch[k] = difpag;
                                            }
                                            else {
                                                results[i].price += difrece;
                                                results[j].price = 0;
                                                results[i].payhowmuch[k] = difrece;
                                            }
                                            results[i].paywho[k] = results[j].person;
                                            j--;
                                            k++;
                                        }
                                    }
                                }
                                for (var i = 0; typeof results[i].price != "undefined" && i < results.length; i++) {
                                    var k = 0;
                                    for (var j = 0; typeof results[i].payhowmuch[j] != "undefined" && j < payhowmuch.length; j++) {
                                        sendTextMessage(senderID, results[i].person + " needs to pay " + results[i].payhowmuch[j] + "€ to " + results[i].paywho[j]);
                                        if (payhowmuch.length > k) {
                                            sendTextMessage(senderID, "and " + results[i].payhowmuch[j] + " € to " + results[i].paywho[j]);
                                        }
                                        k--;
                                    }
                                }
                            } else if (!error && results.length == 2) {
                                sendTextMessage(senderID, "Just give the money to the other guy! You are just two!");
                            } else if (!error && results.length < 2) {
                                sendTextMessage(senderID, "No split needed...");
                            } else {
                                sendTextMessage(senderID, error);
                            }

                        }
                    );
                }

                break;

            default:
                sendTextMessage(senderID, "I'm not sure I understood that... Type 'help' to see the commands I understand.");

        }
    } else if (messageAttachments) {
        sendTextMessage(senderID, "I can't process attachments... Type 'help' to see the commands I understand.");
    }


}


/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var delivery = event.delivery;
    var messageIDs = delivery.mids;
    var watermark = delivery.watermark;
    var sequenceNumber = delivery.seq;

    if (messageIDs) {
        messageIDs.forEach(function (messageID) {
            console.log("Received delivery confirmation for message ID: %s",
                messageID);
        });
    }

    console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 *
 */
function receivedPostback(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfPostback = event.timestamp;

    // The 'payload' param is a developer-defined field which is set in a postback
    // button for Structured Messages.
    var payload = event.postback.payload;

    console.log("Received postback for user %d and page %d with payload '%s' " +
        "at %d", senderID, recipientID, payload, timeOfPostback);

    // When a postback is called, we'll send a message back to the sender to
    // let them know it was successful
    sendTextMessage(senderID, "Postback called");
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 *
 */
function receivedMessageRead(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;

    // All messages before watermark (a timestamp) or sequence have been seen.
    var watermark = event.read.watermark;
    var sequenceNumber = event.read.seq;

    console.log("Received message read event for watermark %d and sequence " +
        "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 *
 */
function receivedAccountLink(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;

    var status = event.account_linking.status;
    var authCode = event.account_linking.authorization_code;

    console.log("Received account link event with for user %d with status %s " +
        "and auth code %s ", senderID, status, authCode);
}

/*
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "image",
                payload: {
                    url: SERVER_URL + "/assets/rift.png"
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a Gif using the Send API.
 *
 */
function sendGifMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "image",
                payload: {
                    url: SERVER_URL + "/assets/instagram_logo.gif"
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send audio using the Send API.
 *
 */
function sendAudioMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "audio",
                payload: {
                    url: SERVER_URL + "/assets/sample.mp3"
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendVideoMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "video",
                payload: {
                    url: SERVER_URL + "/assets/allofus480.mov"
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendFileMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "file",
                payload: {
                    url: SERVER_URL + "/assets/test.txt"
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: messageText,
            metadata: "DEVELOPER_DEFINED_METADATA"
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "button",
                    text: "This is test text",
                    buttons: [{
                        type: "web_url",
                        url: "https://www.oculus.com/en-us/rift/",
                        title: "Open Web URL"
                    }, {
                        type: "postback",
                        title: "Trigger Postback",
                        payload: "DEVELOPED_DEFINED_PAYLOAD"
                    }, {
                        type: "phone_number",
                        title: "Call Phone Number",
                        payload: "+16505551234"
                    }]
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "generic",
                    elements: [{
                        title: "rift",
                        subtitle: "Next-generation virtual reality",
                        item_url: "https://www.oculus.com/en-us/rift/",
                        image_url: SERVER_URL + "/assets/rift.png",
                        buttons: [{
                            type: "web_url",
                            url: "https://www.oculus.com/en-us/rift/",
                            title: "Open Web URL"
                        }, {
                            type: "postback",
                            title: "Call Postback",
                            payload: "Payload for first bubble"
                        }]
                    }, {
                        title: "touch",
                        subtitle: "Your Hands, Now in VR",
                        item_url: "https://www.oculus.com/en-us/touch/",
                        image_url: SERVER_URL + "/assets/touch.png",
                        buttons: [{
                            type: "web_url",
                            url: "https://www.oculus.com/en-us/touch/",
                            title: "Open Web URL"
                        }, {
                            type: "postback",
                            title: "Call Postback",
                            payload: "Payload for second bubble"
                        }]
                    }]
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
    // Generate a random receipt ID as the API requires a unique ID
    var receiptId = "order" + Math.floor(Math.random() * 1000);

    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "receipt",
                    recipient_name: "Peter Chang",
                    order_number: receiptId,
                    currency: "EUR",
                    payment_method: "Visa 1234",
                    timestamp: "1428444852",
                    elements: [{
                        title: "Oculus Rift",
                        subtitle: "Includes: headset, sensor, remote",
                        quantity: 1,
                        price: 599.00,
                        currency: "USD",
                        image_url: SERVER_URL + "/assets/riftsq.png"
                    }, {
                        title: "Samsung Gear VR",
                        subtitle: "Frost White",
                        quantity: 1,
                        price: 99.99,
                        currency: "USD",
                        image_url: SERVER_URL + "/assets/gearvrsq.png"
                    }],
                    address: {
                        street_1: "1 Hacker Way",
                        street_2: "",
                        city: "Menlo Park",
                        postal_code: "94025",
                        state: "CA",
                        country: "US"
                    },
                    summary: {
                        subtotal: 698.99,
                        shipping_cost: 20.00,
                        total_tax: 57.67,
                        total_cost: 626.66
                    },
                    adjustments: [{
                        name: "New Customer Discount",
                        amount: -50
                    }, {
                        name: "$100 Off Coupon",
                        amount: -100
                    }]
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */

function sendQuickYesNo(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: "Hi! My name is Byll, I'm here to help you split your bills with your friends... Type 'help' to see the words I understand :)",
            metadata: "DEVELOPER_DEFINED_METADATA",
            quick_replies: [
                {
                    "content_type": "text",
                    "title": "Help",
                    "payload": "help"
                },
                {
                    "content_type": "text",
                    "title": "Stats",
                    "payload": "stats"
                },
                {
                    "content_type": "text",
                    "title": "Split the bill",
                    "payload": "split the bill"
                }
            ]
        }
    };

    callSendAPI(messageData);
}

function sendQuickReply(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: "What's your favorite movie genre?",
            metadata: "DEVELOPER_DEFINED_METADATA",
            quick_replies: [
                {
                    "content_type": "text",
                    "title": "Action",
                    "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
                },
                {
                    "content_type": "text",
                    "title": "Comedy",
                    "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
                },
                {
                    "content_type": "text",
                    "title": "Drama",
                    "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
                }
            ]
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
    console.log("Sending a read receipt to mark message as seen");

    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: "mark_seen"
    };

    callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
    console.log("Turning typing indicator on");

    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: "typing_on"
    };

    callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
    console.log("Turning typing indicator off");

    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: "typing_off"
    };

    callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "button",
                    text: "Welcome. Link your account.",
                    buttons: [{
                        type: "account_link",
                        url: SERVER_URL + "/authorize"
                    }]
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
    request({
        uri: 'https://graph.facebook.com/v2.6/me/messages',
        qs: {access_token: PAGE_ACCESS_TOKEN},
        method: 'POST',
        json: messageData

    }, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            var recipientId = body.recipient_id;
            var messageId = body.message_id;

            if (messageId) {
                console.log("Successfully sent message with id %s to recipient %s",
                    messageId, recipientId);
            } else {
                console.log("Successfully called Send API for recipient %s",
                    recipientId);
            }
        } else {
            console.error(response.error);
        }
    });
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function () {
    console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
