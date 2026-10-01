const fs=require('fs'),vm=require('vm'),assert=require('assert');
const html=fs.readFileSync(require('path').join(__dirname,'../src/templates/dashboard.html'),'utf8');
let nodes=new Map(),intervals=new Map(),timer=0,blobs=new Map(),downloads=[],calls=[];
function node(id){return {id,textContent:'',innerHTML:'',value:'',checked:false,hidden:false,style:{},dataset:{},listeners:{},classList:{remove(){},add(){},toggle(){}},addEventListener(e,f){this.listeners[e]=f},querySelectorAll(s){return [...this.innerHTML.matchAll(/data-id="([^"]+)"/g)].map(m=>{let b=node('detail');b.dataset.id=m[1];return b})},showModal(){this.open=true},close(){this.open=false},reset(){this.resetCalled=true},click(){downloads.push(this.href)}}}
for(const m of html.matchAll(/id="([^"]+)"/g))nodes.set(m[1],node(m[1]));
const buttons=['','High','Medium','Low'].map(v=>{const b=node('severity');b.dataset.severity=v;return b});
const context={document:{getElementById(id){assert(nodes.has(id),id);return nodes.get(id)},querySelectorAll(s){return s==='.severity-filter'?buttons:[]},createElement(){return node('download')}},URLSearchParams,Map,console:{...console,error(){}},Blob,setTimeout,clearTimeout,confirm:()=>true,
URL:{createObjectURL(b){blobs.set('blob:export',b);return 'blob:export'},revokeObjectURL(){}},
FormData:function(form){const d=new FormData();d.append('file',new Blob([JSON.stringify({message:'File import test',severity:'Low'})]),'events.json');return d},
setInterval(f){intervals.set(++timer,f);return timer},clearInterval(id){intervals.delete(id)},async fetch(path,options){calls.push(path);return fetch(process.env.SIEM_TEST_URL+path,options)}};
vm.runInNewContext(html.split('<script>')[1].split('</script>')[0],context);
const delay=ms=>new Promise(r=>setTimeout(r,ms)),read=id=>nodes.get(id).textContent;
async function tick(){await [...intervals.values()][0]()}
async function settle(){await delay(250)}
(async()=>{
await tick();assert.equal(read('ring-total'),0);assert(nodes.get('timeline').innerHTML.includes('No events'));assert.equal(read('system-status'),'Measured');assert(read('system-memory').endsWith('%'));
const events=[{message:'Failed logon <script>',severity:'High',is_alert:true,rule_name:'Failed logon',channel:'Security',event_id:'4625',provider:'Audit',username:'admin'},{message:'Warning event',severity:'Medium',channel:'System',event_id:'2',provider:'Kernel',username:'user'},{message:'Application event',severity:'Low',channel:'Application',event_id:'3',provider:'App',username:'user'}];
assert.equal((await context.fetch('/api/events',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(events)})).status,201);
await tick();assert.equal(read('count-total'),'3');assert.equal(read('ring-high'),1);assert.equal(read('count-alerts'),'1');assert(nodes.get('timeline').innerHTML.includes('<svg'));assert(nodes.get('log-volume').innerHTML.includes('volume-column'));assert(nodes.get('event-body').innerHTML.includes('&lt;script&gt;'));
for(const [id,value,query] of [['filter-channel','System','channel=System'],['filter-provider','Kernel','provider=Kernel'],['filter-event-id','2','event_id=2'],['filter-user','user','username=user'],['filter-since','5','since=5']]){nodes.get(id).value=value;nodes.get(id).listeners.change();await settle();assert(calls.some(p=>p.includes(query)));nodes.get('reset-filters').listeners.click();await settle();assert.equal(read('count-total'),'3')}
nodes.get('filter-search').value='Failed logon';nodes.get('filter-search').listeners.input();await delay(500);assert.equal(read('count-total'),'1');nodes.get('reset-filters').listeners.click();await settle();
buttons[1].listeners.click();await settle();assert.equal(read('count-total'),'1');nodes.get('reset-filters').listeners.click();await settle();
nodes.get('alerts-only').checked=true;nodes.get('alerts-only').listeners.change();await settle();assert.equal(read('count-total'),'1');nodes.get('reset-filters').listeners.click();await settle();
const body=nodes.get('event-body'),original=body.querySelectorAll,id=body.querySelectorAll()[0].dataset.id;
const detail={dataset:{id},addEventListener(e,f){this.click=f}};body.querySelectorAll=()=>[detail];await tick();detail.click();assert(nodes.get('event-dialog').open);assert(read('detail-raw').length>0);nodes.get('close-dialog').listeners.click();assert(!nodes.get('event-dialog').open);body.querySelectorAll=original;
nodes.get('export-events').listeners.click();assert.equal(downloads.length,1);const csv=await blobs.get(downloads[0]).text();assert(csv.includes('Failed logon <script>'));assert.equal(csv.split('\r\n').length,4);
nodes.get('live-toggle').listeners.click();assert.equal(read('live-label'),'PAUSED');assert.equal(intervals.size,0);nodes.get('live-toggle').listeners.click();await settle();assert.equal(read('live-label'),'LIVE');assert.equal(intervals.size,1);
const form=nodes.get('file-form');await form.listeners.submit({preventDefault(){},currentTarget:form});await settle();assert.equal(read('count-total'),'4');assert(form.resetCalled);
const working=context.fetch;context.fetch=async()=>{throw Error('Disconnected')};await tick();assert.equal(nodes.get('connection-notice').hidden,false);await form.listeners.submit({preventDefault(){},currentTarget:form});assert(read('ingest-message').includes('connection unavailable'));context.fetch=working;await tick();assert.equal(nodes.get('connection-notice').hidden,true);
await nodes.get('clear-events').listeners.click();await settle();assert.equal(read('count-total'),'0');
console.log('PASS: charts, metrics, all filters, reset, escaped text, details, export, pause/resume, import, disconnection/recovery and clear.');
})().catch(e=>{console.error(e);process.exitCode=1});
