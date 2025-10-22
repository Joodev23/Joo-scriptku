const fs   = require('fs');
const path = require('path');
const chalk= require('chalk');

function rainbowLog(text){
  const colors=[
    chalk.hex('#FF5252').bold,
    chalk.hex('#FF9800').bold,
    chalk.hex('#FFEB3B').bold,
    chalk.hex('#4CAF50').bold,
    chalk.hex('#00BCD4').bold,
    chalk.hex('#2196F3').bold,
    chalk.hex('#3F51B5').bold,
    chalk.hex('#9C27B0').bold,
    chalk.hex('#E91E63').bold,
    chalk.hex('#FFFFFF').bold
  ];
  let out='';
  for(let i=0;i<text.length;i++) out+= colors[i%colors.length](text[i]);
  console.log(out);
}

const R=[
  /(?<!['"`])\baxios\s*\.\s*interceptors\s*\.\s*request\s*\.\s*use\s*=\s*/i,
  /(?<!['"`])\baxios\s*\.\s*interceptors\s*\.\s*request\s*\.\s*handlers\s*=\s*\[\s*\]/i,
  /(?<!['"`])\bprocess\.exit\s*=\s*(new\s+Proxy|function\s*\()/i,
  /(?<!['"`])\bprocess\.kill\s*=\s*(new\s+Proxy|function\s*\()/i,
  /(?<!['"`])\bprocess\.on\s*\(\s*['"]uncaughtException/i,
  /(?<!['"`])\bprocess\.on\s*\(\s*['"]unhandledRejection/i
];
const h=d=>R.some(r=>r.test(d));
const clean=src=>src
  .replace(/\/\/.*$/gm,'')
  .replace(/\/\*[\s\S]*?\*\//g,'')
  .replace(/(["'`])((?!\1)[\\]|.)*?\1/g,'');

function protect(filePath){
  const src = fs.readFileSync(filePath,'utf8');
  if(h(clean(src))){
    rainbowLog('[ ! ] Threat Detected – Execution Blocked');
    return false;
  }
  return true;
}

function JooModss(){
  const T=__filename;
  const L=path.join(path.dirname(T),'shield-alert.log');

  const g=()=>{try{return fs.readFileSync(T,'utf8')}catch{return null}};
  const s=m=>{try{fs.appendFileSync(L,`[ 7ooModdss ] ${m}\n`)}catch{}};
  const die=(w,x)=>{
    rainbowLog(`[ 7ooModdss ] ${w}`);
    if(x) try{fs.writeFileSync(T,x.replace(/./gs,' '),{mode:0o600})}catch{}
    process.exit(1);
  };

  ((_=>_&&h(clean(_))&&die('boot',_))(g()));

  fs.watchFile(T,{interval:600},()=>{
    const _=g();
    !_?die('lost'):h(clean(_))&&die('live',_);
  });

  const w=fs.writeFileSync;
  fs.writeFileSync=function(file,data,opts){
    const str=String(data);
    if(path.resolve(String(file))===T && h(clean(str))) die('write',str);
    return w.call(this,file,data,opts);
  };

  rainbowLog('7ooModdss Shield Activated');
}

module.exports={protect, JooModss, rainbowLog};