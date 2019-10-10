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
  request = require('request');

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

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
app.get('/webhook', function(req, res) {
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
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
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
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

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
  messageText = trime(messageText);
  var messageAttachments = message.attachments;
  console.log("messageAttachments"+messageAttachments);
  var quickReply = message.quick_reply;
  // this is log maintainance
  question = messageText;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s",
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);

      // THIS MODULE IS FOR PROCESSING THE USER CLICKED QUICK REPLIES

      //showing the readReciept to make more realistic 
      sendReadReceipt(senderID);
      wait();
      //showing typing effect
      sendTypingOn(senderID);
      wait();
      console.log(message.text);

      //complaint box 

      var messageText = message.text;
      //messageText = trime(messageText);
      messageText = messageText.toLowerCase();

     if(messageText.indexOf('.')>0)
     {

      //this will be used if quicky reply is big and displayed as "abc..."
      //this function will give the original sentence which could be used for further processing
       messageText=findString(messageText,currentIndex);
       //this variable will used for log maintaince
       question = messageText;
     }
     console.log(messageText +" "+ currentIndex+" ");
    
      if(messageText.toLowerCase()==="Give your Feedback".toLowerCase())
      {
        //enabling the feedbackProcess module now all request will redirect to feedbackProcess box
        manipulate(senderID,"You are being redirected to FeedBack section");
 
       feedbackProcess=true;
      }
         //this will work when user click on register complaint or reqquest for complaint
      if(messageText.toLowerCase()==="Issue or Complaint".toLowerCase())
      {
        //enabling the complaint module now all request will redirect to complaint box
        //here no use of l
        manipulate(senderID,"You are being redirected to complaint section");
      
       complaintProcessIndex=true;
      }

     if(feedbackProcess==true)
     {
      console.log("inside feedbackIndex :"+ feedbackIndex);

        if(feedbackIndex!=0){
              feedbackProcess=false;
              feedbackIndex=0;
              sendTextMessage(senderID,"Your feedback process has been aborted, i hope you are being served well");
      
        }
        else{
             console.log("process FeedBack");
            feedback(senderID,messageText);
        }
     }
      else if(complaintProcessIndex == true)
        {
          //process the complaint
          
          //if user click on quick reply during complaint procedure.
          console.log("inside complaintProcessIndex :"+ complaintProcessIndex);

          if(complaintIndex!=0)
          {
            //(clicked the quick reply) if index is not equal means proess has been aborted by the user
            complaintIndex=0;
            complaintProcessIndex=false;
            //now all request will be treated normally
            sendTextMessage(senderID,"Your complaint process has been aborted Thanks for your concern");
          }
          else{
              console.log("process complaint");
              //starting the complaint process
               processComplaint(senderID,messageText);
          }
       }
       else{
          //manipulate will give the related answer to clicked quick reply if found any issue or unable to give answer then return -1 means no response is generated yet.
          var k = manipulate(senderID,messageText);
           if(k==-1)
           {
              //process something : it will give sorry -. as bot is unable to understand the user query
              logUnknownQuestion(senderID,question,"Sorry, I didn't get you");
              //there is question with sorry -> it will process this for sure;
              k = manipulate(senderID,"Sorry, I didn't get you");
           }
       }
       //as answer is sent then turn off the typing
      sendTypingOff(senderID);
    return;
  }

  // THIS MODULE IS FOR PROCESSING THE USER INPUT 
  if (messageText) {

    //removing leading and trailing spaces
    messageText = trime(messageText);
    messageText = messageText.toLowerCase();
    //creating realistic view
    sendReadReceipt(senderID);
    wait();
    sendTypingOn(senderID);
    wait();
    console.log("inside function");
    console.log(messageText);

    if(messageText.includes("feedback") || messageText.includes("feed")&&messageText.includes("back"))
    {
        if(feedbackProcess!=true)
          manipulate(senderID,"You are being redirected to FeedBack section");
        feedbackProcess = true;
        wait(1000);
    }
    //enable the complaint process if user input contains below mentioned words
    if(messageText.includes("complaint") || messageText.includes("query") || messageText.includes("issue"))
    {
        if(complaintProcessIndex!=true){
           manipulate(senderID,"You are being redirected to complaint section");
        }
        complaintProcessIndex=true;
        // this is to notify user that you have been redirected.
        wait(1000);
    }

    //proces feedback
    if(feedbackProcess==true)
    {
      feedback(senderID,messageText);
    }
    //processing complain
     else if(complaintProcessIndex == true)
      {
        //process the complaint
        
        //all user input will give pass to this during complaint procedure.
        processComplaint(senderID,messageText);
     }
    else if(first)
        {
          //initial message
          sendQuickReply(senderID,0);
         first = false;
      }
     else if(true)
     {
        var p = manipulate(senderID,"Please select the below mentioned suggestions");
     }
     else{
        if(first)
        {
          //initial message
          sendQuickReply(senderID,0);
         first = false;
        }
      else
      {
        //processing the rest/general user input
        var check = processing(senderID,messageText);
       //if unable to generate output
       if(check == -1)
       {
          //maintaining the logs 
         logUnknownQuestion(senderID,question,"Sorry, I didn't get you");
          //generating sorry output
          check = manipulate(senderID,"Sorry, I didn't get you");
       }
      //messageText=messageText.replace(/[^\w\s]/gi, '').trim().toLowerCase();

        sendTypingOff(senderID);
    
      }
     }
  }  else if (messageAttachments) {
    sendTextMessage(senderID, "Please be specific");
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
    messageIDs.forEach(function(messageID) {
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
 * If users came here through testdrive, they need to configure the server URL
 * in default.json before they can access local resources likes images/videos.
 */
function requiresServerURL(next, [recipientId, ...args]) {
  if (SERVER_URL === "to_be_set_manually") {
    var messageData = {
      recipient: {
        id: recipientId
      },
      message: {
        text: `
We have static resources like images and videos available to test, but you need to update the code you downloaded earlier to tell us your current server url.
1. Stop your node server by typing ctrl-c
2. Paste the result you got from running "lt —port 5000" into your config/default.json file as the "serverURL".
3. Re-run "node app.js"
Once you've finished these steps, try typing “video” or “image”.
        `
      }
    }

    callSendAPI(messageData);
  } else {
    next.apply(this, [recipientId, ...args]);
  }
}

function sendHiMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: `Hello, welcome to Wishfin. how may i help you?`
    }
  }

  callSendAPI(messageData);
}



function sendTextMessage(recipientId, messageText,check) {
  if(check == true)
    logFile(recipientId,question,messageText);
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
  //dbinsert(question,messageText,recipientId);
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
          buttons:[{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Trigger Postback",
            payload: "DEVELOPER_DEFINED_PAYLOAD"
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
              payload: "Payload for first bubble",
            }],
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
              payload: "Payload for second bubble",
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
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
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
        
 var ignoreDataLog = ["You are being redirected to FeedBack section","You are being redirected to Complaint section",
 "Please Enter Correct/valid required field or want to abort the process please click below at welcome to wishfin"]
function sendQuickReply(recipientId,index) {
  //generating output from question bank. access the output using index
  var check = true;

  for(i in ignoreDataLog)
  {
    if(question.toLowerCase().trim()===ignoreDataLog[i].toLowerCase().trim())
      {
        check=false;
        break;
      }
     // for giving direction messages like incorrect input etc.
    console.log("send Quick Reply ignoreDataLog\n"+data[index].question+"  "+ignoreDataLog[i]);
    if(data[index].question.toLowerCase().trim()===ignoreDataLog[i].toLowerCase().trim())
      {
        check=false;
        break;
      }
  }
  if(check)
  {
    logFile(recipientId,question,data[index].answer);
  }

  console.log(question+" "+JSON.stringify(data[index]));
  var reply = [];
  console.log("inside quick reply");
  for(var i =0 ;i<data[index].replies.length;i++)
  {
    //creating quick replies
      reply.push({
          "content_type":"text",
          "title":data[index].replies[i],
          "payload":"DEVELOPER_DEFINED_PAYLOAD"
        });
     // console.log(reply);
  }
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      //generating the answer for user input.
      text: data[index].answer,
      quick_replies : reply
      /*text: "What's your favorite movie genre?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]*/
    }
  };

  callSendAPI(messageData);
  //dbinsert(question,data[index].answer,recipientId);
}
function sendQuickReplyModified(recipientId,object) {
//generating output from question bank. access the output using object  
  logFile(recipientId,question,object.answer);


  var reply = [];
  console.log("inside quick reply modified");
  console.log(object);
  console.log(" complaint index " + object + " " + object.replies );
  for(var i =0 ;i<object.replies.length;i++)
  {
    //generating quick replies 
      reply.push({
          "content_type":"text",
          "title":object.replies[i],
          "payload":"DEVELOPER_DEFINED_PAYLOAD"
        });
     // console.log(reply);
  }
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      //generating output
      text: object.answer,
      quick_replies : reply
      /*text: "What's your favorite movie genre?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]*/
    }
  };

  callSendAPI(messageData);
  //dbinsert(question,object.answer,recipientId);
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
          buttons:[{
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
    qs: { access_token: PAGE_ACCESS_TOKEN },
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
      sendTextMessage(recipientId,"There is some error please type again or contact after some time");
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
// My Parameter

//this is our question bank for getting output
var first = true;
var data = [
    {   id:1,
        question : "Welcome to Wishfin",
        replies : [
            //"questions about Wishfin",
              //  "I am a customer",
            "Free CIBIL Score",
            "Get a Home Loan",
            "Get a Personal Loan",
            "Get a Car Loan",
            "Get Credit Cards",
            "Mutual Funds",
            "Savings Account",
            "Contact Sales Team",
            "Issue or Complaint",
            "Give your Feedback"
        ],
        answer : "Welcome to Wishfin. I am WishChat, a chatbot. How can I fulfill your wish?"
    },
    {   id:2,
        question : "questions about Wishfin",
        replies : [
            "about Wishfin",
                "Loans provided by us"
        ],
        answer : "Please select your below mentioned options!"
    },
    {   id:3,
        question : "about Wishfin",
        replies : [
            "About Us",
            "check the website on my own",
            "want to know more?"
        ],
        answer:"WishFin is a platform run by Mywish Marketplaces Private Limited (MMPL). MMPL has pioneered financial marketplaces in India. It runs neutral financial marketplaces that leverage its proprietary technology to intermediate between the banks and customers seeking banking products."
    },
    {   id:4,
        question : "About Us",
        replies : [
            "Welcome to Wishfin"
        ],
        answer : "Welcome to Wishfin, India's largest financial services marketplace. Now, for the first time, Wishfin brings its world of  Financial Enablement to Facebook Chat. Whether it is Loans, Mutual Funds or Cibil Score Check, you can experience this revolution right here, right now...\nPlease do our section :- About Us(https://www.wishfin.com/about-us)"
    },
    {   id:5,
        question : "check the website on my own",
        replies : [
            "Welcome to Wishfin"
        ],
        answer : "please refer our website : https://www.wishfin.com"
    },
    {   id:6,
        question : "want to know more?",
        replies : [
            "Our Investors",
            "Media Coverage",
            "How can I get a Loan"  
        ],
        answer : "Please choose your interest?"
    },
    {   id:7,
        question : "Our Investors",
        replies : [
            "Welcome to Wishfin"
        ],
        answer : "Please do refer this website : https://www.wishfin.com/about-us"
    },
    {   id:8,
        question : "Media Coverage",
        replies : [
        "want to know more?",
            "Welcome to Wishfin"
        ],
        answer : "Please do refer https://www.wishfin.com/about-us"
    },
    {   id:9,
        question : "How can I get a Loan",
        replies : [
          "want to know more?",
          "Welcome to Wishfin"
        ],
        answer : " You can get loan upto 50 lakhs please do refer : https://www.wishfin.com/"
    },
    {   id:10,
        question : "what is wishfin wf",
        replies : [
         "About Us",
            "check the website on my own",
            "want to know more?"
        ],
        answer : "WishFin is a platform run by Mywish Marketplaces Private Limited (MMPL). MMPL has pioneered financial marketplaces in India. It runs neutral financial marketplaces that leverage its proprietary technology to intermediate between the banks and customers seeking banking products."
    },
    {   id:11,
        question : "Loans provided by us",
        replies : [
        "want to know more?",
         "Welcome to Wishfin"
        ],
        answer : "You can get loan upto 50 lakhs"
    },
    {   id:12,
        question : "Want To start Again",
        replies : [
            "Welcome to Wishfin"
        ],
        answer : "Kindly select below to start again"
    },
    {   id:13,
        question : "Free CIBIL Score",
        replies : [
            "Show other loans",
            "Welcome to Wishfin"
        ],
        answer : "Please do refer https://www.wishfin.com/cibil-score"
    },
    {   id:14,
        question : "Show other loans",
        replies : [
             "Get a Home Loan",
            "Get a Personal Loan",
            "Get a Car Loan",
            "Get Credit Cards",
            "Mutual Funds",
            "Savings Account",
            "Contact Sales Team"
        ],
        answer :"Please select type of loan"
    },
    {   id:15,
        question : "I am a customer",
        replies : [
            "Get a Home Loan",
            "Get a Personal Loan",
            "Get a Car Loan",
            "Get Credit Cards",
            "Mutual Funds",
            "Savings Account",
            "When Can I Get The Loan",
            "Contact Sales Team"
        ],
        answer : "Hello sir/ma'am kindly select below the type of loan"
    },
    {   id:16,
        question : "Get a Home Loan",
        replies : [
        "Show other loans",
            "Welcome to Wishfin"
        ],
        answer : "Please refer this site for home loans https://www.wishfin.com/home-loan"
    },
    {   id:17,
        question : "Get a Personal Loan",
        replies : [
        "Show other loans",
            "Welcome to Wishfin"
        ],
        answer : "Please refer this site for perosnal loans https://www.wishfin.com/personal-loan"
    },
    {   id:18,
        question : "Get a Car Loan",
        replies : [
        "Show other loans",
        "When Can I Get The Loan",
            "Welcome to Wishfin"
        ],
        answer : "Please refer this site for car loans https://www.wishfin.com/car-loan"
    },
    {   id:19,
        question : "Get Credit Cards",
        replies : [
        "Show other loans",
         "Welcome to Wishfin"
        ],
        answer : "Please refer this site for credit cards loans : https://www.wishfin.com/credit-cards"
    },
    {   id:20,
        question : "Mutual Funds",
        replies : [
        "Show other loans",
         "Welcome to Wishfin"
        ],
        answer : "Please refer this site for mutual funds loan loans https://mutualfund.wishfin.com/?utm_source=Wishfin&utm_medium=Homepage&utm_campaign=Navigation"
    },
    {   id:21,
        question : "Savings Account",
        replies : [
         "Show other loans",
         "Welcome to Wishfin"
        ],
        answer : "Please refer this site for saving account https://www.wishfin.com/saving-account"
    },
    {   id:22,
        question : "Contact Sales Team",
        replies : [
        "Welcome to Wishfin",
        "Show other loans"
        ],
        answer : "Kindly contact here : - +91-8882935454"
    },
    {   id:23,
        question : "When Can I Get The Loan",
        replies : [
          "Show other loans",
         "Welcome to Wishfin"
        ],
        answer : "You can get the loan with in 7 days of processing"
    },
    {   id:24,
        question : "what is your name who are you what people call you",
        replies : [
            "questions about Wishfin",
                "I am a customer",
            "Free CIBIL Score"
        ],
        answer : "My name is Wishfin Chat"
    },
    {   id:25,
        question : "You can get a loan of amount upto 50 lakhs",
        replies : [
            "Get a Home Loan",
            "Get a Personal Loan",
            "Get a Car Loan",
            "Get Credit Cards",
            "Mutual Funds",
            "Savings Account",
            "When Can I Get The Loan",
            "Contact Sales Team"
        ],
        answer : "You can get a loan of amount upto 50 lakhs, Please select type of loan"
    },
    {   id:26,
        question : "register your complaint",
        replies : [
           "Welcome to Wishfin"
        ],
        answer : "Thank You for giving us your complaint. We will back to you soon."
    },
    {   id:27,
        question : "Issue or Complaint",
        replies : [
            "register your complaint", "Give your Feedback",
            "Contact Sales Team",
            "Welcome to Wishfin"
        ],
        answer : "Sorry for inconvenience. Please Contact the concern person : +91-8882935454"
    },
    {   id:28,
        question : "Sorry, I didn't get you",
        replies : [
             "Welcome to Wishfin"
        ],
        answer : "Sorry! i didn't get you , what do you want to say, please say again"
    },
    {   id:29,
        question : "need personal loan, get PL",
        replies : [
          "Show other loans",
            "Welcome to Wishfin"
        ],
        answer : "Please refer this site for perosnal loans https://www.wishfin.com/personal-loan"
    },
    {   id:30,
        question : "i want a car loan, need a car loan, how can i get the car loan",
        replies : [
       "Show other loans",
            "Contact Sales Team"
        ],
        answer : "Please refer this site for car loans https://www.wishfin.com/car-loan"
    },
    {   id:31,
        question : "do you provide i want a education loan, need a education loan, how can i get the education loan",
        replies : [
        "Show other loans",
            "Welcome to Wishfin"
        ],
        answer : "Please refer this site for education loan https://www.wishfin.com/"
    },
    {   id:32,
        question : "i want a home loan, need a home loan, how can i get the home loan HL",
        replies : [
          "Show other loans",
          "Contact Sales Team",
            "Welcome to Wishfin"
        ],
        answer : "Please refer this site for home loans https://www.wishfin.com/home-loan"
    },
    {   id:33,
        question : "mutual funds know , idea",
        replies : [
        "Contact Sales Team",
           "Show other loans",
            "Welcome to Wishfin"
        ],
        answer : "A mutual fund is a type of financial vehicle made up of a pool of money collected from many investors to invest in securities such as stocks, bonds, money market instruments, and other assets. For more detail Please refer this site for mutual funds loan loans https://mutualfund.wishfin.com/?utm_source=Wishfin&utm_medium=Homepage&utm_campaign=Navigation"
    },
    {   id:34,
        question : "status of application or loan",
        replies : [
            "Show other loans",
            "Welcome to Wishfin",
            "Contact Sales Team"
        ],
        answer : "Please contact Sales team"
    },
    {   id:35,
        question : "why i have not recieved my money why i am getting delayed in getting my loan amount",
        replies : [
        "Free CIBIL Score",
            "Welcome to Wishfin",
            "Contact Sales Team"
        ],
        answer : "Please Contact Sales Team"
    },
    {   id:36,
        question : "when will i get my money of loan , why i am getting delayed in getting my loan amount",
        replies : [
            "Contact Sales Team",
           "Free CIBIL Score"
        ],
        answer : "Your loan amount will be transferred shortly"
    },
    {   id:37,
        question : "how are you ?",
        replies : [
               "Welcome to Wishfin"
        ],
        answer : "I am fine, what about you ? "
    },
    {   id:38,
        question : " i am ok , fine , good , cool ",
        replies : [
               "Welcome to Wishfin",
                "Contact Sales Team"
        ],
        answer : "Thats great, please click below to select your queries"
    },
    {   id:39,
        question : "i need your help , i have a query , i need to ask you a question , please help me out",
        replies : [
        "Issue or Complaint",
              "Welcome to Wishfin",
                "Contact Sales Team"
        ],
        answer : "How may i help ?"
    },
    {   id:40,
        question : "email , address , contact , number , toll free no. customer care how can i connect with your sales team",
        replies : [
        "Welcome to Wishfin",
        "Show other loans"
        ],
        answer : "Kindly contact here : - +91-8882935454  \n Email : gaurang.goel@wishfin \n address : E-30 noida sector 8 near metro station sector 15"
    },
    {   id:41,
        question : "facebook page , fb",
        replies : [
               "Welcome to Wishfin",
        "Show other loans"
        ],
        answer : "https://www.facebook.com/wishfinofficial/"
    },
    {   id:42,
        question : "instagram , page  insta",
        replies : [
        "Contact Sales Team",
              "Welcome to Wishfin",
        "Show other loans"
        ],
        answer : "Sorry, we dont have any instagram page, kindly refer to our website https://www.wishfin.com or faceboo page  https://www.facebook.com/wishfinofficial/"
    },
    {   id:43,
        question : "fuck , suck , fuckoff , morron get lost , fucker , motherfucker , bustard , stupid wtf ass hole morron dumb ",
        replies : [
               "Contact Sales Team"
        ],
        answer : "language please!"
    },
    {   id:44,
        question : "want car loan , home loan , travelling loan , personal , educational and any other loan ",
         replies : [
             "Get a Home Loan",
            "Get a Personal Loan",
            "Get a Car Loan",
            "Get Credit Cards",
            "Mutual Funds",
            "Savings Account",
            "Contact Sales Team"
        ],
        answer :"Please select type of loan"
    },
    {   id:45,
        question : "what services are provided by you , wishfin whishfin wf , company , institution , firm , organization",
        replies : [
        "Issue or Complaint",
              "Welcome to Wishfin",
              "Contact Sales Team","Give your Feedback"


        ],
        answer : " We provide loans , mutual funds , saving account etc."
    },
    {   id:46,
        question : "mf sip",
        replies : [
               "Contact Sales Team",
           "Show other loans",
            "Welcome to Wishfin","Give your Feedback"
        ],
        answer : "A mutual fund is a type of financial vehicle made up of a pool of money collected from many investors to invest in securities such as stocks, bonds, money market instruments, and other assets. For more detail Please refer this site for mutual funds loan loans https://mutualfund.wishfin.com/?utm_source=Wishfin&utm_medium=Homepage&utm_campaign=Navigation"
    },
    {   id:47,
        question : "good service job exellent work thanks you love bye",
        replies : [
        "Show other loans",
              "Welcome to Wishfin"
        ],
        answer : "Thanks for your response!. It's our pleasure to serve you well, please visit again at https://www.wishfin.com and allow us to serve you again"
    },
    {   id:48,
        question : "wishfin your organization head , owner , ceo , mentor , senior , boss",
        replies : [
               "Show other loans",
               "Welcome to Wishfin"
        ],
        answer : "Our CEO is Mr. Rishi Mehra. He is a great personality. Under his experience, this company has achieved alot of success kindly contact him on linkdin : https://www.linkedin.com/in/rishi-mehra-60b93113/?originalSubdomain=in and our mentor Suyash Gupta, Under his guidence , we took our product at this stage kindly contact him on linkdin :https://www.linkedin.com/in/suyash-gupta-77006839/ "
    },
    {   id:49,
        question : "any success stories , story , article , blogs , writeups , write ",
        replies : [
              "Free CIBIL Score",
            "Welcome to Wishfin",
            "Contact Sales Team"
        ],
        answer : "Please find the relevant information on this website : https://www.wishfin.com/blog/"
    },
    {   id:50,
        question : "diff different diferentiate differences between b/w bw mf mutual funds loan vs v/s versus",
        replies : [
               "Free CIBIL Score",
               "Welcome to Wishfin"
        ],
        answer : "there are various difference between loan and mutual funds. For such differences you can visit this web page : https://cleartax.in/s/loan-against-mutual-funds"
    },
    {   id:51,
        question : "leave me alone don't  talk shut up get lost",
        replies : [
               "Issue or Complaint","Give your Feedback",
             "Show other loans",
                "Contact Sales Team"
        ],
        answer : "Ok! your wish , thanks for visiting. Please do visit again"

    },
    {   id:52,
        question : "hello hi hey wassup",
        replies : [
               "Welcome to Wishfin",
                "Contact Sales Team"
        ],
        answer : "hello, its great to you see you on board"
    },
    {   id:53,
        question : "want need credit cards loans CC ",
        replies : [
        "Show other loans",
               "Welcome to Wishfin","Give your Feedback",
                "Contact Sales Team"
        ],
        answer : "Please refer this site for credit cards loans : https://www.wishfin.com/credit-cards"
    },
    {   id:54,
        question : "which loan can i get",
        replies : [
             "Get a Home Loan",
            "Get a Personal Loan",
            "Get a Car Loan",
            "Get Credit Cards",
            "Mutual Funds",
            "Savings Account",
            "Contact Sales Team"
        ],
        answer :"Please select type of loan"
    },
    {   id:55,
        question : "what is my cibil score",
        replies : [
            "Show other loans",
            "Welcome to Wishfin"
        ],
        answer : "Please do refer https://www.wishfin.com/cibil-score"
    }
    ,
    {   id:56,
        question : "what is will be the interest rates",
        replies : [
            "Show other loans",
            "Contact Sales Team",
            "Welcome to Wishfin"
        ],
        answer : "Please refer this site for perosnal loans https://www.wishfin.com/personal-loan and https://www.wishfin.com/home-loan or you can connect with our sales teams"
    }
    ,
    {   id:57,
        question : "Please select the below mentioned suggestions",
        replies : [
            "Welcome to Wishfin",
            "Issue or Complaint",
            "Contact Sales Team", 
            "Give your Feedback", 
            "about Wishfin",
                "Loans provided by us"
        ],
        answer : "Please select the below mentioned suggestions"
    },
    {   id:58,
        question : "your service is pathetic ,  worse , useless ",
        replies : [
            "Contact Sales Team",
            "register your complaint","Give your Feedback"
        ],
        answer : "Sorry for inconvenience. Please Contact the concern person : +91-8882935454"
    },
    {   id:59,
        question : "Give your Feedback",
        replies : [
           "Contact Sales Team",
            "register your complaint"
        ],
        answer : "Thank You for giving us your Feedback."
    },
    //these are for complaint and feedback section
    {   id:60,
        question : "You are being redirected to FeedBack section",
        replies : [
          "Abort Your Process"
        ],
        answer : "You are being redirected to FeedBack section"
    },
    {   id:61,
        question : "You are being redirected to Complaint section",
        replies : [
          "Abort Your Process"
        ],
        answer : "You are being redirected to Complaint section"
    },
    {   id:62,
        question : "Please Enter Correct/valid required field or want to abort the process please click below at welcome to wishfin",
        replies : [
          "Abort Your Process"
        ],
        answer : "Please Enter Correct/valid required field or want to abort the process please click below at welcome to wishfin"
    }
    
    
];
//"Please Enter Correct/valid required field or want to abort the process please click below at welcome to wishfin"

//let enlargedata = [];

//this is our question bank for general processing

var phrases = [
"fuck , suck , fuckoff , morron get lost , fucker , motherfucker , bustard , stupid wtf ass hole morron dumb ",
"hello hi hey wassup",
"how are you ?",
"which loan can i get",
"leave me alone don't  talk shut up get lost",
" i am ok , fine , good , cool ",
"good service job exellent work thanks you love bye",
"need personal loan, get PL",
"mutual funds know , idea",
"i need your help , i have a query , i need to ask you a question , please help me out",
"Issue or Complaint",
"want need credit cards loans CC ",
"register your complaint","what is wishfin wf",
"what is your name who are you what people call you","You can get a loan of amount upto 50 lakhs",
"time period of your loan is of 3 years",
"Your emi of loan is 30,000 per month","Your emi of loan will be 30,000 per month",
"Your balance principal amount is 3,50,000",
"i want a car loan, need a car loan, how can i get the car loan",
"do you provide i want a education loan, need a education loan, how can i get the education loan",
"i want a home loan, need a home loan, how can i get the home loan HL",
"status of application or loan",
"Your application is in processing phase, would you like to contact us through call",
"why i have not recieved my money why i am getting delayed in getting my loan amount",
"when will i get my money of loan , why i am getting delayed in getting my loan amount",
"Your loan amount will be transferred shortly",
"Your loan is on the way",
"We will get back to you","When Can I Get The Loan",
"Your application has some issues",
"I couldn't get what you are saying","Welcome to Wishfin","questions about Wishfin","about Wishfin",
"About Us","check the website on my own","want to know more?",
"Our Investors","Media Coverage","How can I get a Loan",
"Loans provided by us","Want To start Again","Free CIBIL Score","what is my cibil score",
"Show other loans","I am a customer","Get a Home Loan",
"Get a Personal Loan","Get a Car Loan","Get Credit Cards","Mutual Funds",
"Savings Account","Contact Sales Team",
"email , address , contact , number , toll free no. customer care how can i connect with your sales team",
"facebook page , fb",
"instagram , page  insta",
"mf sip",
"want car loan , home loan , travelling loan , personal , educational and any other loan ",
"what services are provided by you , wishfin whishfin wf , company , institution , firm , organization",
"wishfin your organization head , owner , ceo , mentor , senior , boss",
"any success stories , story , article , blogs , writeups , write ", 
"diff different diferentiate differences between b/w bw mf mutual funds loan vs v/s versus",
"your service is pathetic ,  worse , useless ",
"what is will be the interest rates","Give your Feedback"
]

var fs = require('fs');
//var phrases1 = fs.readFileSync("phrases.txt").toString();
//phrases.append(phrases1);
//phrases.push(phrases1);
//console.log("global"+phrases);
 //var enlargedata = fs.readFileSync("BotContent.json").toString();
//console.log("global"+enlargedata);


//this is a functinon using to get the clicked quick reply from question bank and generating the output
function manipulate(recipientId,message){
    console.log("reached");
    console.log(message);
    for( var i in data)
    {
      //console.log(i);
      //console.log(data[i].question);
      //console.log(message);

      //matching which question matches with the clicked quick reply
      if(message.length>0 && data[i].question.toLowerCase().trim()==message.toLowerCase().trim())
      {
        //console.log("generating quick reply");
        //console.log(i);
        currentIndex=i;
        sendQuickReply(recipientId,i);
        return 0 ;
      }
    }
    return -1;
}
function manipulateForBotContent(recipientId,message){
    console.log("reached in manipulate for bot content");
    console.log("message"+message);
    try{
      for( var i in enlargedata)
    {
      //console.log(i);
      //console.log(enlargedata[i].question);
      //console.log(message);

      //matching which question matches with the clicked quick reply
      if(message.length>0 && enlargedata[i].question.toLowerCase().trim()==message.toLowerCase().trim())
      {
        //console.log("generating quick reply");
        //console.log(i);
        currentIndex=i;
        sendTextMessage(recipientId,enlargedata[i].answer,true);
        return 0 ;
      }
    }
    }
    catch(e)
    {
      console.log(e);
    }
    return -1;
}

var currentIndex = 0;
//this is code used for generating the original clicked quick reply as replies can be displayed with ... if length of quick reply is greater than 20 character
function findString(message , currentIndex)
{
  //using the currect index to find which quick replies has been displayed
  var reply = data[currentIndex].replies;
  var backup = message;
  message = message.slice(0,message.length-3);
  console.log("findString =========================");
  //console.log(message);
  for(var i = 0 ; i<reply.length;i++)
  {
    //console.log(reply[i].slice(0,message.length));

    //finding which quick reply has been clicked.
    if(reply[i].slice(0,message.length).toLowerCase().trim()==message.toLowerCase().trim())
    {
   //   console.log(reply[i]);
      return reply[i];
    }
  }

  //returning the original quickreply if thee is no slicing.
  return backup;
}


//removing stop words
var sw = require('stopword');
function removeStopWords(message){
    try {
      
      var oldMessage = message.split(" ");
    var newMessage = sw.removeStopwords(oldMessage);
    return newMessage;
    } catch (e) {
      console.log("inside removeStopWords"+e);
      return message;
    }
}

//lemmetize the words
var lemmer = require('lemmer').Lemmer;
function lemmetization(word)
{
  //var lemmerEng = new lemmer('english');  
  try{
      return lemmer.lemmatize(word);
  }
  catch(e)
  {
      console.log("inside lemmetization"+e);
      return word;
  }
}

//generating the best response for user input.
function processing(senderID,message)
{
  console.log("processing" +message);
 //console.log("phrases :" + phrases[10]);
  
  //removing the unwanted character like ?., etc.
  message = filterString(message); 

  //convert the strings into the tokens
  var arr = removeStopWords(message);
  
  console.log("message token" + arr);
  var content = arr;
  //var content = [];
  /*for(var i =0 ;i<arr.length;i++)
  {
    if(arr[i].length>1)
    {
      //creating a list of tokens
      content.push(arr[i]);
    }
  }*/

    // console.log("content token" + content);
  
    var index =[];

    for(var i=0;i<content.length;i++)
    {
      //console.log(content[i]);
      
      //find the possibilities of getting the phrase for given token and do this for all tokens
      content[i]=lemmetization(content[i]);
      for(var j = 0 ;j<phrases.length;j++)
      {
        //finding the token in the string of questions and answer.
        if(phrases[j].toLowerCase().includes(content[i].toLowerCase()))
          index.push(j);
          //index is holding the index of phrases which could be the result.
      }
    }
    //console.log("index token" + index);
    
    //sorting the indexes so that answer can be get on the priority basis. 
    index = index.sort(function(a, b){ 
      return a-b;
    });

    //console.log("index token" + index);
    
    //what if there is no result related to given string then return -1 which infere no result then generate sorry message

    if(index.length>0)
    {
      var i = maxFreq(index);
      //getting the output phrase
      var messagePhrase = phrases[i];
      //console.log("message Phrase : "+messagePhrase);

      //generating the output for given phrase
      var check  = manipulate(senderID,messagePhrase);
      //here -1 means -> there is not response in our database
      if(check == -1)
        {
          console.log("inside procesing - check condition " + messagePhrase);

          var c = manipulateForBotContent(senderID,messagePhrase);

          if(c==-1)
              sendTextMessage(senderID,messagePhrase,true);
        }
        //here zero means single response has been generated 
      return 0;
    }
    return -1;
}


//this is used for removing the characters like ?., etc. from the given input.
function filterString(message)
{
  console.log("filter string");
  var str = "";
  for(var i =0 ; i<message.length;i++)
  {
    //console.log(i+"inside filter string " + message[i]);
  
  console.log(message[i].charCodeAt(0));
  console.log(message[i].charCodeAt(0)<97);

  //removing all characters except space
    if(message[i] == ' ')
    {
      //console.log(i+" 32 " + message[i]);
  
         str += message[i]; 
    }
    else if(message[i]<'a' || message[i]>'z' )
    {
      //console.log(i+" continue " + message[i]);
  
      continue; 
    }
    else{
      //console.log(i+" else " + message[i]);
      str += message[i];
    }
    console.log(str);
  }
  return str;
}

// removing the leading and trailing spaces 
function trime(messageText){
  if(messageText!=null || messageText!="")
  {
    //messageText = messageText.trim();
  }
  return messageText;
}


//finding the element which has a highest frequency. element is a index which holds the result phrase
function maxFreq(arr1){
let mf = 0;
let m = 0;
let item;
for (let i=0; i<arr1.length; i++)
{
        for (let j=i; j<arr1.length; j++)
        {
                if (arr1[i] == arr1[j])
                 m++;
                if (mf<m)
                {
                  mf=m; 
                  item = arr1[i];
                }
        }
        m=0;
}
return item;
}




//constant wait
function wait(){
  setTimeout(function(){}, 500); 
}

//variable watiting
function wait(time){
  setTimeout(function(){}, time); 
}


//set of questions need to ask to user to entertain the complaint
var complaint =  [
    {        
        question : "What is you name ?",
        replies : [
               "Abort Your Process"
        ],
        answer : "Hello sir, welcome to complaint/feedback section, What is you name ?"
    },
    {   
        question : "What is your 10 digit Phone Number ?",
        replies : [
               "Abort Your Process"
        ],
        answer : "What is your 10 digit Phone Number ?"
    },
    {   
        question : "what is your email id ?",
        replies : [
               "Abort Your Process"
        ],
        answer : "what is your email id ?"
    },
    {   
        question : "what is your complaint/feedback ?",
        replies : [
               "Abort Your Process"
        ],
        answer : "what is your complaint/feedback ?"
    },
    {   
        question : "This is your Query Please check it again Answer as y or n",
        replies : [
               "Abort Your Process"
        ],
        answer : " " 
    }
]



var complaintProcessIndex = false;
var complaintIndex = 0;

//holding the details of user during the complaint processing.
var userComplaint = {
  userName :" ",
  userNumber :" ",
  userEmail :" ",
  userComplaint:" "
}

//it will process the complaint
function processComplaint(senderID,message){
  console.log("inside process complaint" + complaintIndex);
  console.log("process complaint" + complaintProcessIndex);

  //if complaint index = 0 then ask user name
  if(complaintIndex == 0)
  {
    console.log(complaintIndex+" query index " + senderID);
    sendQuickReplyModified(senderID,complaint[complaintIndex]);
    complaintIndex++;
  }
  // if index is 4 then ask for proof reading
  else if(complaintIndex == 4)
  {
     setData(message,complaintIndex,userComplaint);
    console.log(complaintIndex+" query index " + senderID);
    complaint[complaintIndex].answer=    "Your name is :"+userComplaint.userName + "\nYour userNumber is : " + userComplaint.userNumber + "\nyour email id is :" + userComplaint.userEmail + "\nyour complaint is : " + userComplaint.userComplaint +"\nThis is your Query Please check it again Answer as y or n to complete or abort the complaint process";

    sendQuickReplyModified(senderID,complaint[complaintIndex]);
    complaintIndex++;
  }
  //if index is 5 then ask for yes or no (want to accept and abort the complaint process)
  else if(complaintIndex==5)
    {
      if(message.includes("y"))
      {
        //it is for mail 
        userComplaint.content = 'Hello '+userComplaint.userName+'\nYour complaint "'+userComplaint.userComplaint+'" has been registered and we will be back to you soon to resolve your issue.\nSorry for the inconvenience. \n\n\nRegards, \nGaurang\n(Wishfin IT Support)';
        saveProcess(senderID,userComplaint,"ComplaintData.json");
        sendTextMessage(senderID,"Thanks for registering your query/complaint, we will get back to you soon",true); 
      }
      else
        sendTextMessage(senderID,"your complain process is aborted",true); 
      complaintIndex = 0;
      complaintProcessIndex = false;
  }
  //for index 1-3 (general work)
 else 
  {

    var k = verification(message,complaintIndex);
    //verify the previous input if correct move on else ask for again input
    if(k==0)
    {
      //if verification passes
      setData(message,complaintIndex,userComplaint);
     // sendTextMessage(senderID,"Please Enter Correct/valid required field");
      sendQuickReplyModified(senderID,complaint[complaintIndex]);
      complaintIndex++;
    }
    else{
      //if verification fails
        

        manipulate(senderID,"Please Enter Correct/valid required field or want to abort the process please click below at welcome to wishfin");
        wait(1000);
        sendQuickReplyModified(senderID,complaint[complaintIndex-1]);   
    }
  }
}

//setting the data in userComplaint object
function setData(message,index,object)
{
  if(index==1)
    object.userName=message;
  if(index==2)
    object.userNumber=message;
  if(index==3)
    object.userEmail=message;
  if(index==4 && feedbackProcess==true)
    object.userFeedBack=message;
  if(index==4)
    object.userComplaint=message;
}

//verfication of user input for complaint process.
function verification(message,index){
  console.log("inside verification ");
  console.log("message " + message);
  console.log("index" + index);

//verification of name
  if(index==1)
  {
    /*for(var i =0 ;i<message.length;i++)
      console.log("inside verification "+ message[i]);
      if(message[i]==' ')
        continue;
      if(message[i]<'a' || message[i]>'z')
      {
        console.log("name verification is failed"+message[i])
        return -1;
      }
    return 0;*/

    var letters = /^[A-Za-z_ ]+$/;
      if(!message.match(letters))
      {
        console.log("name verification is failed"+message);
        return -1;
      }
      return 0;
  }

//verification of age
  if(index==2)
  {
    if(isNaN(message))
      return -1;
    if(message.length!=10)
      return -1;
    return 0; 
  }

//verification of email
  if(index==3)
  {
    if(message.includes("@") >0 && message.includes(".")>0)
      {
        var k = message.split("@");
        if(k[0].length<1)
          return -1;
        if(k[1].length<6)
          return -1;
        return 0;
      }
    return -1;
  } 
  if(index==4)
  {
    //no verification required for complaint;
    return 0;
  }

}

var question = "";

//generating an object for logs maintainance
function getTheObject(senderID,question,answer){
  return {"SenderId" : ""+senderID, "question":""+question,"answer":""+answer};
}

//creating a log
function logFile(senderID,question,answer){
    //select file
   // var fs = require('fs')
    //get the data
    var user = getTheObject(senderID,question,answer);    
 
fs.readFile('FacebookChatBotData.json', function (err, data) {
  if(err)
    {
      console.log("FacebookChatBotData logs" + err);
        //sendTextMessage(senderID,"Hello, I have encountered some error. please do ask some other question or contact after sometime");
    }
        var json = JSON.parse(data)
        //console.log(json);
        //append the log into the data
        json.push(user)
        // save the data
        //fs.writeFile("FacebookChatBotData.json", JSON.stringify(json));
        fs.writeFile("FacebookChatBotData.json", JSON.stringify(json), function(err, result) {
         if(err) console.log('error', err);
       });
    });

}

//THIS IS USED TO MAINTAIN LOGS USING DATABASE(MongoDB)


/*var MongoClient = require('mongodb').MongoClient;
var url = "mongodb://localhost:27017/";

function dbinsertG(message,response,id){
  var obj={
    user:message,
    chatbot:response
  }
  var newobj={
    id:id,
    chat:[{
    question:message,
    answer:response
    }]
  }
  MongoClient.connect(url,{ useNewUrlParser: true },function(err,db){
    if(err)throw err;
    var dbo=db.db("wishfin");
    var query={id:id};
    dbo.collection("conversation").findOne(query,function(err,result){
      if(err)throw err;

      if(result){
        result.chat.push(obj)
        var newvalue={$set:result}
          dbo.collection("conversation").updateOne(query,newvalue,function(err,res){
          if(err) throw err;
          console.log("value inserted")
        })
      }
      else{
        dbo.collection("conversation").insertOne(newobj,function(err,res){
          if(err) throw err;
          console.log("value inserted")
        })
      }
    db.close();
    })
  })
} */                         

/*function dbinsert(message,response,id=1){
  
  var obj={
    SenderId:id,
    question:message,
    answer:response
    }
  MongoClient.connect(url,function(err,db){
    if(err)throw err;
    var dbo=db.db("wishfin");
    
        dbo.collection("conversation1").insertOne(obj,function(err,res){
          if(err) throw err;
          console.log("value inserted")

        })
        db.close();
      })
}*/                          

 //var fs = require('fs');
//storing the question which is not answered by chatbot.
function logUnknownQuestion(senderID,question,answer){
    //select file
    //var fs = require('fs')
    //get the data
    var user = getTheObject(senderID,question,answer);    
 
fs.readFile('UnknownQuestionData.json', function (err, data) {
    if(err)
    {
      consle.log("error in UnknownQuestionData"+err);
        //sendTextMessage(senderID,"Hello, I have encountered some error. please do ask some other question or contact after sometime");
    }
    var json = JSON.parse(data)
    //append the log into the data
    json.push(user)
    // save the data
    //fs.writeFile("FacebookChatBotData.json", JSON.stringify(json));
    fs.writeFile("UnknownQuestionData.json", JSON.stringify(json), function(err, result) {
     if(err) console.log('error', err);
   });
});

}

//storing the complaints in json file for future processing.
function saveProcess(senderID,query,fileName){
    //select file
 //   var fs = require('fs')
    //get the data

    query["senderId"] = senderID;
    var user = query ;//getTheObject(senderID,question,answer);    
 
fs.readFile(fileName, function (err, data) {
  if(err)
    {
        sendTextMessage(senderID,"Hello, I have encountered some error. please do ask some other question or contact after sometime",true);
    }
    var json = JSON.parse(data)
    //append the log into the data
    json.push(user)
    // save the data
    //fs.writeFile("ComplaintData.json", JSON.stringify(json));
    
    mailComplaint(user);
    fs.writeFile(fileName, JSON.stringify(json), function(err, result) {
     if(err) console.log('error', err);
   });
});

}

//used to send the email to user for confirmation of email registration

function mailComplaint(user){
  console.log("mailing the complaint");
  console.log(user);
  var nodemailer = require('nodemailer');
  //accessing the sender's address and authenticate the account
  var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'gaurang.goel@wishfin.com',
      pass: 'friendsoffriends'
    }
  });

  console.log('feedback logs' +feedbackProcess);
  console.log('complaint logs' +complaintProcessIndex);
  //preparing the mail for the user from sender's address 
  var mailOptions = {
    from: 'gaurang.goel@wishfin.com',
    to: user.userEmail,
    subject: 'Complaint/FeedBack Registration Confirmation',
    text: user.content
  };
  //sent the mail from sender's address
  transporter.sendMail(mailOptions, function(error, info){
    if (error) {
      console.log(error);
    } else {
      console.log('Email sent: ' + info.response);
    }
  });
}


//FeedBack Module.

var feedbackProcess = false;
var feedbackIndex = 0;

//holding the details of user during the complaint processing.
var userFeedBack = {
  userName :" ",
  userNumber :" ",
  userEmail :" ",
  userFeedBack:" "
}
function feedback(senderID,message){
  console.log("inside feedback complaint" + feedbackIndex);
  console.log(feedbackProcess);
  //if complaint index = 0 then ask user name
  if(feedbackIndex == 0)
  {
    console.log(feedbackIndex+" query index " + senderID);
    sendQuickReplyModified(senderID,complaint[feedbackIndex]);
    feedbackIndex++;
  }
  // if index is 4 then ask for proof reading
  else if(feedbackIndex == 4)
  {
     setData(message,feedbackIndex,userFeedBack);
    console.log(feedbackIndex+" query index " + senderID);
    complaint[feedbackIndex].answer=    "Your name is :"+userFeedBack.userName + "\nYour age is : " + userFeedBack.userNumber + "\nyour email id is :" + userFeedBack.userEmail + "\nyour feedback is : " + userFeedBack.userFeedBack +"\nThis is your feedback Please check it again Answer as y or n to complete or abort the feedback process";

    sendQuickReplyModified(senderID,complaint[feedbackIndex]);
    feedbackIndex++;
  }
  //if index is 5 then ask for yes or no (want to accept and abort the complaint process)
  else if(feedbackIndex==5)
    {
      if(message.includes("y"))
      {  userFeedBack.content='Hello '+userFeedBack.userName+'\nYour feedback "'+userFeedBack.userFeedBack+'" has been registered.\nThanks for your feedback. its great to serve you \n\n\nRegards, \nGaurang\n(Wishfin IT Support)';
    
        saveProcess(senderID,userFeedBack,"FeedBack.json");
        sendTextMessage(senderID,"Thanks for registering your query/feedback, we will get back to you soon",true); 
      }
      else
        sendTextMessage(senderID,"your feedback process is aborted",true); 
      feedbackIndex = 0;
      feedbackProcess = false;
  }
  //for index 1-3 (general work)
 else 
  {

    var k = verification(message,feedbackIndex);
    //verify the previous input if correct move on else ask for again input
    if(k==0)
    {
      //if verification passes
      setData(message,feedbackIndex,userFeedBack);
     // sendTextMessage(senderID,"Please Enter Correct/valid required field");
      sendQuickReplyModified(senderID,complaint[feedbackIndex]);
      feedbackIndex++;
    }
    else{
      //if verification fails
        manipulate(senderID,"Please Enter Correct/valid required field or want to abort the process please click below at welcome to wishfin");
        wait(1000);
        sendQuickReplyModified(senderID,complaint[feedbackIndex-1]);   
    }
  }
}


