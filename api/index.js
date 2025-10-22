const {protect} = require('../lib/shield');
const path=require('path');

module.exports=(req,res)=>{
  const {file}=req.query;
  if(!file) return res.status(400).json({error:'Missing ?file=path'});
  const full=path.resolve(String(file));
  const threat=!protect(full);
  res.json({file:full, threat});
};