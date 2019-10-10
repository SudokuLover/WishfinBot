let enlargedata=[]
let phrases=[]
var fs = require('file-system');
function enlargedataSet(){
    console.log("running");
       fs.readFile('BotContent.json', function (err, data) {
    if(err)
    {
      consle.log("error in hardCoded"+err);
    }
    var json = JSON.stringify(JSON.parse(data));
    //console.log(json);
    for(var i in json)
    {
        //console.log(i);
        enlargedata.push(json[i]);
    }
    
});
fs.readFile('phrases.txt', function (err, data) {
    if(err)
    {
      consle.log("error in hardCoded"+err);
    }
    
    var json = JSON.stringify(data)
    for(var i in json)
    {
        phrases.push(json[i]);
    } 
});

}


console.log(enlargedata);
console.log(phrases);
console.log("before");
enlargedataSet();
console.log("after");
//wait(1000);
console.log(enlargedata);
console.log(phrases);




var global_data = fs.readFileSync("phrases.txt").toString();
//console.log("global"+global_data);
 global_data = fs.readFileSync("BotContent.json").toString();
console.log("global"+global_data);