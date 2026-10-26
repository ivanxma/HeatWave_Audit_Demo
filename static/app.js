'use strict';
const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
const csrf = $('meta[name="csrf-token"]').content;
function el(tag, attrs={}, text) { const n=document.createElement(tag); for(const [k,v] of Object.entries(attrs)) { if(k==='class') n.className=v; else n.setAttribute(k,v); } if(text!==undefined) n.textContent=text; return n; }
function tabs(root) {
 const buttons=$$(':scope > .tabs > [role="tab"]',root);
 buttons.forEach(b=>b.onclick=()=>{buttons.forEach(x=>{const active=x===b;x.classList.toggle('active',active);x.setAttribute('aria-selected',String(active));document.getElementById(x.dataset.tab).hidden=!active;});root.dispatchEvent(new CustomEvent('tabchange',{detail:b.dataset.tab}));});
 buttons.forEach((b,i)=>b.onkeydown=e=>{if(['ArrowLeft','ArrowRight'].includes(e.key)){e.preventDefault();const next=buttons[(i+(e.key==='ArrowRight'?1:-1)+buttons.length)%buttons.length];next.focus();next.click();}});
}
$$('[data-tabs]').forEach(tabs);
const dialog=$('#value-dialog');
$('[data-close-dialog]').onclick=()=>dialog.close();
function valueText(v){return v===null?'NULL':typeof v==='object'?JSON.stringify(v,null,2):String(v);}
function fullValue(v){$('#full-value').textContent=valueText(v);dialog.showModal();}
document.addEventListener('keydown',e=>{if(e.key==='Escape') $$('details[open]').forEach(d=>d.open=false);});
document.addEventListener('click',e=>$$('.topbar details[open]').forEach(d=>{if(!d.contains(e.target))d.open=false;}));
async function api(path,data){ const res=await fetch('/api/'+path,{method:data===undefined?'GET':'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:data===undefined?undefined:JSON.stringify(data)});const result=await res.json();if(!res.ok)throw new Error(result.error||'Request failed.');return result; }
function message(text,error=false){const target=$('#messages');if(!target)return;const bar=el('div',{class:'message '+(error?'error':'success'),role:'status'});bar.append(el('span',{},text));const close=el('button',{class:'icon','aria-label':'Dismiss message'},'×');close.onclick=()=>{const focused=bar.contains(document.activeElement);bar.remove();if(focused)($('#messages [aria-label="Dismiss message"]')||$('#notifications summary'))?.focus();};bar.append(close);target.append(bar);}
async function notifications(){if(!$('#notifications'))return;const data=await api('notifications');$('#notification-count').textContent=data.messages.length;$('#notification-count').hidden=!data.messages.length;$('#notifications summary').setAttribute('aria-label','Notifications, '+data.messages.length+' messages');$('#clear-notifications').disabled=!data.messages.length;const list=$('#notification-list');list.replaceChildren();if(!data.messages.length)list.textContent='No notifications.';data.messages.forEach(m=>{const n=el('div',{class:'notification'});n.append(el('small',{},m.category+' · '+m.time),el('p',{},m.message));list.append(n);});}
if($('#clear-notifications')){ $('#clear-notifications').onclick=async()=>{try{await api('notifications/clear',{});await notifications();}catch(e){message(e.message,true);notifications().catch(()=>{});}};notifications().catch(()=>{});}
const workspace=$('.workspace');
if(workspace){
 const outputPanel=$('.results-panel');outputPanel.id='execution-output';
 const outputDialog=el('dialog',{id:'output-dialog',class:'output-dialog','aria-label':'Execution output'});
 const maximizeButton=el('button',{id:'maximize-output',type:'button',class:'icon',title:'Maximize execution output','aria-label':'Maximize execution output','aria-expanded':'false','aria-controls':'execution-output'},'⛶');
 const outputActions=el('div',{class:'output-actions'});outputActions.append($('#result-count'),maximizeButton);$('.panel-heading',outputPanel).append(outputActions);document.body.append(outputDialog);
 const outputAnchor=document.createComment('Execution output position');outputPanel.before(outputAnchor);
 function restoreOutput(){
  outputDialog.close();outputAnchor.after(outputPanel);document.documentElement.classList.remove('output-maximized');
  maximizeButton.textContent='⛶';maximizeButton.title='Maximize execution output';maximizeButton.setAttribute('aria-label',maximizeButton.title);maximizeButton.setAttribute('aria-expanded','false');maximizeButton.focus({preventScroll:true});
 }
 maximizeButton.onclick=()=>{
  if(outputDialog.open){restoreOutput();return;}
  outputDialog.append(outputPanel);document.documentElement.classList.add('output-maximized');
  maximizeButton.textContent='⤢';maximizeButton.title='Restore execution output';maximizeButton.setAttribute('aria-label',maximizeButton.title);maximizeButton.setAttribute('aria-expanded','true');outputDialog.showModal();maximizeButton.focus();
 };
 outputDialog.addEventListener('cancel',event=>{event.preventDefault();restoreOutput();});
 const page=workspace.dataset.page;
 let token=null, action=null, busy=false, advancedEdited=false;
 const classInfo={connection:{events:['connect','change_user','disconnect'],fields:['status','user.str','host.str','ip.str']},general:{events:['status'],fields:['general_sql_command.str','general_error_code','general_query.str']},table_access:{events:['read','insert','update','delete'],fields:['table_database.str','table_name.str']},message:{events:['internal','user'],fields:[]}};
 function invalidate(){token=null;$('#execute').disabled=true;$('#plan-status').textContent='Settings changed · preview SQL';}
 workspace.addEventListener('input',e=>{if(!e.target.closest('#output'))invalidate();});
 workspace.addEventListener('change',e=>{if(!e.target.closest('#output'))invalidate();});
 function select(options,value){const s=el('select');options.forEach(x=>s.append(el('option',{value:x},x||'No field match')));s.value=value;return s;}
 function labeled(text,input){const label=el('label',{},text);label.append(input);return label;}
 function addRule(name='general'){
  const box=el('div',{class:'rule'}), header=el('div',{class:'rule-heading'});
  const cls=select(Object.keys(classInfo),name);cls.className='rule-class';cls.setAttribute('aria-label','Event class');
  const toggle=el('input',{type:'checkbox',class:'rule-enabled',checked:''}), toggleLabel=el('label',{class:'checkbox-field'},'Log enabled');toggleLabel.prepend(toggle);
  const del=el('button',{class:'icon','aria-label':'Remove rule',title:'Remove rule'},'×');del.onclick=()=>{box.remove();invalidate();};
  header.append(cls,toggleLabel,del);box.append(header);
  const details=el('div');box.append(details);
  function update(){details.replaceChildren();const events=el('div',{class:'event-options'});classInfo[cls.value].events.forEach(e=>{const input=el('input',{type:'checkbox',value:e,class:'rule-event',checked:''});const label=el('label',{class:'checkbox-field'},e);label.prepend(input);events.append(label);});
   const field=select(['',...classInfo[cls.value].fields],'');field.className='rule-field';const value=el('input',{class:'rule-value',placeholder:'Exact match value',disabled:''});value.setAttribute('aria-label','Match value');field.onchange=()=>{value.disabled=!field.value;};const grid=el('div',{class:'form-grid'});grid.append(labeled('Match field',field),labeled('Equals',value));details.append(events,grid);invalidate();
  }
  cls.onchange=update;$('#rules').append(box);update();
 }
 function rules(){return $$('.rule').map(r=>({class:$('.rule-class',r).value,enabled:$('.rule-enabled',r).checked,events:$$('.rule-event:checked',r).map(x=>x.value),field:$('.rule-field',r).value,value:$('.rule-value',r).value}));}
 function easyDefinition(){const scope=$('#scope').value;if(scope!=='rules')return {filter:{log:scope==='all'}};return {filter:{log:false,class:rules().map(r=>{const match=r.enabled?(r.field?{field:{name:r.field,value:['status','general_error_code'].includes(r.field)&&/^\d+$/.test(r.value)?Number(r.value):r.value}}:true):false;return r.events.length?{name:r.class,event:r.events.map(name=>({name,log:match}))}:{name:r.class,log:match};})}};}
 if(page==='filters'){
  addRule();$('#add-rule').onclick=()=>{const used=rules().map(r=>r.class);addRule(Object.keys(classInfo).find(n=>!used.includes(n))||'connection');};
  function syncEasy(){
   const scope=$('#scope').value;
   $('#rules').hidden=scope!=='rules';$('#add-rule').hidden=scope!=='rules';
   $('#scope-help').textContent=scope==='all'?'Log is true for every auditable event. No class or event definition is required.':scope==='none'?'Log is false for every event. No class definition is required.':'Log is false by default. Only the selected classes and matching events are logged.';
   const obj=easyDefinition();$('#definition').value=JSON.stringify(obj,null,2);advancedEdited=false;
   $('#definition-preview').hidden=false;$('#definition-preview').open=true;$('#json-preview').textContent=JSON.stringify(obj,null,2);
  }
  $('#scope').onchange=syncEasy;
  $('#easy').addEventListener('input',syncEasy);$('#easy').addEventListener('change',syncEasy);
  const ruleObserver=new MutationObserver(syncEasy);ruleObserver.observe($('#rules'),{childList:true});
  syncEasy();
  const regenerate=()=>{$('#definition').value=JSON.stringify(easyDefinition(),null,2);advancedEdited=true;invalidate();};
  $('#regenerate').onclick=regenerate;$('#definition').oninput=()=>advancedEdited=true;
  $('[data-tabs]').addEventListener('tabchange',e=>{if(e.detail==='advanced'&&!advancedEdited)regenerate();invalidate();});
 }
 if(page==='reader')$('#start-mode').onchange=()=>{$('#timestamp-fields').hidden=$('#start-mode').value==='bookmark';$('#id-field').hidden=$('#start-mode').value!=='position';};
 if(page==='analytics'){
  $('#toggle-new-db').onclick=()=>$('#new-db-fields').hidden=!$('#new-db-fields').hidden;
  $('#timing').onchange=()=>{$('#seconds-field').hidden=$('#timing').value!=='relative';$('#analytics-timestamp-field').hidden=$('#timing').value!=='timestamp';};
  $('#select-all').onclick=()=>{$$('[name="audit-column"]').forEach(c=>c.checked=true);invalidate();};$('#select-none').onclick=()=>{$$('[name="audit-column"]').forEach(c=>c.checked=false);invalidate();};
 }
 function val(id,fallback=''){return $('#'+id)?.value??fallback;}
 function payload(op){const d={action:op};if(page==='filters')Object.assign(d,{name:val('filter-name'),account:val('account'),scope:val('scope'),rules:rules(),mode:$('#advanced').hidden?'easy':'advanced',definition:val('definition')});
 if(page==='reader')Object.assign(d,{start_mode:val('start-mode'),timestamp:val('timestamp'),event_id:val('event-id')});
 if(page==='analytics')Object.assign(d,{database:op==='create_database'?val('new-database'):val('database'),view:val('view-name'),timing:val('timing'),seconds:val('seconds'),timestamp:val('analytics-timestamp'),replace:$('#replace-view').checked,columns:$$('[name="audit-column"]:checked').map(x=>x.value)});
 return Object.assign(d,{buffer_size:val('buffer-size','32768'),max_events:val('max-events','100')});}
 function setBusy(value){busy=value;$$('[data-operation]').forEach(b=>b.disabled=value);$('#execute').disabled=value||!token;}
 $$('[data-operation]').forEach(b=>b.onclick=async()=>{if(busy)return;setBusy(true);invalidate();try{const data=await api('preview',payload(b.dataset.operation));token=data.token;action=b.dataset.operation;$('#sql-preview').textContent=data.sql;$('#plan-status').textContent='Ready · '+action.replaceAll('_',' ');$('#definition-preview').hidden=!data.definition;if(data.definition)$('#json-preview').textContent=JSON.stringify(data.definition,null,2);}catch(e){message(e.message,true);notifications().catch(()=>{});}finally{setBusy(false);}});
 $('#execute').onclick=async()=>{if(busy||!token)return;setBusy(true);const executing=token;token=null;try{const data=await api('execute',{token:executing});message(data.message);renderOutput(data);if(page==='analytics'&&action==='databases'){const s=$('#database');s.replaceChildren();(data.results[0]?.rows||[]).forEach(row=>{const name=Object.values(row)[0];s.append(el('option',{value:name},name));});}if(page==='analytics'&&action==='create_database')message('Database created. Load databases again to select it.');await notifications();$('#plan-status').textContent='Completed · preview to run again';}catch(e){message(e.message,true);notifications().catch(()=>{});$('#plan-status').textContent='Execution failed · preview again';}finally{setBusy(false);}};
 $('#copy-sql').onclick=async()=>{try{await navigator.clipboard.writeText($('#sql-preview').textContent);message('SQL copied.');}catch{message('Select the SQL text to copy it.',true);}};
 function renderOutput(data){
  const output=$('#output');output.replaceChildren();
  const sqlResults=data.results.map((r,i)=>({...r,sourceIndex:i+1,label:r.columns.includes('reader_arguments')?`Reader arguments (SQL ${i+1})`:r.columns.includes('events')?`Raw JSON (SQL ${i+1})`:r.columns.includes('bookmark')?'Bookmark':`Result ${i+1}`}));
  const eventViews=[];
  for(const result of sqlResults){
   let hasArray=false;const rows=[];
   for(const row of result.rows){
    if(typeof row.events==='string'){
     try{const events=JSON.parse(row.events);if(Array.isArray(events)){hasArray=true;rows.push(...events.filter(x=>x&&typeof x==='object'));}}catch{}
    }
   }
   if(hasArray)eventViews.push({columns:[...new Set(rows.flatMap(x=>Object.keys(x)))],rows,label:'Audit events',derived:true});
  }
  const results=[...eventViews,...sqlResults];
  if(eventViews.length)output.append(el('p',{class:'hint'},`${sqlResults.length} SQL result ${sqlResults.length===1?'set':'sets'} returned. Audit events presents the raw JSON as table rows.`));
  if(data.warnings.length)output.append(el('p',{class:'warning'},`MySQL warnings: ${data.warnings.map(w=>w.level+' '+w.code).join(', ')}. For read buffer warnings, increase the buffer and restart from an earlier position; oversized events may have been skipped.`));
  const tabsRoot=el('div',{class:'tab-view'}),tabBar=el('div',{class:'tabs',role:'tablist'});tabsRoot.append(tabBar);
  results.forEach((r,i)=>{const id='result-'+i;tabBar.append(el('button',{role:'tab','aria-selected':String(i===0),'data-tab':id,class:i===0?'active':''},r.label));const panel=el('section',{id,role:'tabpanel'});panel.hidden=i!==0;panel.append(table(r,'audit-'+page+'-'+r.label));tabsRoot.append(panel);});
  if(!results.length)output.append(el('p',{class:'hint'},'Statement completed. No rows returned.'));else{output.append(tabsRoot);tabs(tabsRoot);}
  const counted=eventViews.length?eventViews:sqlResults;
  const total=counted.reduce((n,r)=>n+r.rows.length,0);
  $('#result-count').textContent=total+(eventViews.length?' events':' rows');
 }

 function table(result,key){
  const root=el('div',{class:'data-grid'}),toolbar=el('div',{class:'table-toolbar'}),pager=el('div',{class:'pager'}),icons=el('div',{class:'table-icons'});
  const prev=el('button',{class:'icon',title:'Previous page','aria-label':'Previous page'},'‹'),next=el('button',{class:'icon',title:'Next page','aria-label':'Next page'},'›'),status=el('span');pager.append(prev,status,next);
  const search=el('input',{type:'search',placeholder:'Search results…','aria-label':'Search results'}),csv=el('button',{class:'icon',title:'Export CSV','aria-label':'Export CSV'},'↓'),reset=el('button',{class:'icon',title:'Reset table layout','aria-label':'Reset table layout'},'↺');icons.append(search,csv,reset);toolbar.append(pager,icons);root.append(toolbar);
  const wrap=el('div',{class:'table-scroll'}),t=el('table');wrap.append(t);root.append(wrap);
  let columns=[...result.columns],widths={},sort=null,asc=true,pageNo=0;
  try{const saved=JSON.parse(localStorage.getItem(key)||'null');if(saved&&saved.columns?.length===columns.length&&saved.columns.every(c=>columns.includes(c))){columns=saved.columns;widths=saved.widths||{};}}catch{}
  const save=()=>{try{localStorage.setItem(key,JSON.stringify({columns,widths}));}catch{}};
  function filtered(){const q=search.value.toLowerCase();let rows=result.rows.filter(r=>columns.some(c=>valueText(r[c]).toLowerCase().includes(q)));if(sort)rows=rows.slice().sort((a,b)=>{const av=a[sort],bv=b[sort];return (typeof av==='number'&&typeof bv==='number'?av-bv:valueText(av).localeCompare(valueText(bv)))*(asc?1:-1);});return rows;}
  function draw(){t.replaceChildren();const rows=filtered(),count=Math.max(1,Math.ceil(rows.length/15));pageNo=Math.min(pageNo,count-1);status.textContent=`${pageNo+1} / ${count} · ${rows.length} rows`;prev.disabled=pageNo===0;next.disabled=pageNo>=count-1;
   const head=el('thead'),tr=el('tr');columns.forEach(c=>{const th=el('th',{draggable:'true'}),b=el('button',{},c+(sort===c?(asc?' ↑':' ↓'):''));th.style.width=(widths[c]||180)+'px';b.onclick=()=>{asc=sort===c?!asc:true;sort=c;draw();};th.append(b);th.ondragstart=e=>e.dataTransfer.setData('text/plain',c);th.ondragover=e=>e.preventDefault();th.ondrop=e=>{e.preventDefault();const source=e.dataTransfer.getData('text/plain');if(columns.includes(source)){columns.splice(columns.indexOf(source),1);columns.splice(columns.indexOf(c),0,source);save();draw();}};
    const handle=el('span',{class:'resize-handle',title:'Drag to resize'});handle.onpointerdown=e=>{e.preventDefault();e.stopPropagation();th.draggable=false;const start=e.clientX,w=th.getBoundingClientRect().width;const move=ev=>{widths[c]=Math.max(100,w+ev.clientX-start);th.style.width=widths[c]+'px';};const up=()=>{document.removeEventListener('pointermove',move);document.removeEventListener('pointerup',up);th.draggable=true;save();};document.addEventListener('pointermove',move);document.addEventListener('pointerup',up);};th.append(handle);tr.append(th);});head.append(tr);t.append(head);const body=el('tbody');rows.slice(pageNo*15,(pageNo+1)*15).forEach(row=>{const tr=el('tr');columns.forEach(c=>{const td=el('td'),b=el('button',{class:'cell',title:'Click to view full value'},valueText(row[c]??null));b.onclick=()=>fullValue(row[c]??null);td.append(b);tr.append(td);});body.append(tr);});t.append(body);if(!rows.length){const tr=el('tr'),td=el('td',{colspan:Math.max(1,columns.length)},'No matching rows.');tr.append(td);body.append(tr);}}
  prev.onclick=()=>{pageNo--;draw();};next.onclick=()=>{pageNo++;draw();};search.oninput=()=>{pageNo=0;draw();};reset.onclick=()=>{columns=[...result.columns];widths={};save();draw();};
  csv.onclick=()=>{const quote=v=>'"'+valueText(v).replaceAll('"','""')+'"';const safe=v=>{const s=valueText(v);return /^[=+@\-\t\r]/.test(s)?"'"+s:s;};const lines=[columns,...filtered().map(r=>columns.map(c=>safe(r[c]??null)))];const a=el('a',{href:URL.createObjectURL(new Blob(['\ufeff'+lines.map(r=>r.map(quote).join(',')).join('\r\n')],{type:'text/csv;charset=utf-8'})),download:'audit-results.csv'});a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);};draw();return root;
 }
}
