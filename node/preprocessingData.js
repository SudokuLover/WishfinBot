let content =[];
let phrases=[];

function logFile(){
    //select file
var fs = require('fs')
    //get the data
let l=100;
fs.readFile('hardCoded.json', function (err, data) {
  if(err)
    {
      console.log("hardCoded logs" + err);
        //sendTextMessage(senderID,"Hello, I have encountered some error. please do ask some other question or contact after sometime");
    }
        var json = JSON.parse(data)
        
        for(var i in json)
        {
          var p =json[i];
          content.push(getTheObject(l,p.question,p.answer));
          phrases.push(p.question);
          //console.log(json[i]);
          l++;
        }

fs.readFile('BotContent.json', function (err, data) {
  if(err)
    {
      console.log("botcontent logs" + err);
        //sendTextMessage(senderID,"Hello, I have encountered some error. please do ask some other question or contact after sometime");
    }
        var json = JSON.parse(data)

        for(var i =0;i<content.length;i++)
        {
          json.push(content[i]);
          console.log(content[i]);
        }
      fs.writeFile("BotContent.json", JSON.stringify(json), function(err, result) {
         if(err) console.log('error', err);
       });
    });


fs.readFile('phrases.txt', function (err, data) {
  if(err)
    {
      console.log("phrases logs" + err);
        //sendTextMessage(senderID,"Hello, I have encountered some error. please do ask some other question or contact after sometime");
    }
        var json = JSON.parse(data)
        
       
        for(var i =0;i<phrases.length;i++)
        {
          json.push(phrases[i]);
          console.log(content[i]);
       
        }
      fs.writeFile("phrases.txt", JSON.stringify(json), function(err, result) {
         if(err) console.log('error', err);
       });

       
    });

       
    });

}

/* fs.writeFile("BotContent.json", JSON.stringify(content), function(err, result) {
         if(err) console.log('error', err);
       });
        fs.writeFile("phrases.txt", phrases, function(err, result) {
         if(err) console.log('error', err);
       });*/

function getTheObject(id,question,answer){
  return {"id" : ""+id, "question":""+question,"answer":""+answer};
}
logFile();