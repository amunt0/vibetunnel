var rr=Object.create;var Nt=Object.defineProperty;var is=Object.getOwnPropertyDescriptor;var nr=Object.getOwnPropertyNames;var or=Object.getPrototypeOf,ar=Object.prototype.hasOwnProperty;var zt=(h,t)=>()=>(h&&(t=h(h=0)),t);var lr=(h,t)=>()=>(t||h((t={exports:{}}).exports,t),t.exports),ss=(h,t)=>{for(var e in t)Nt(h,e,{get:t[e],enumerable:!0})},cr=(h,t,e,i)=>{if(t&&typeof t=="object"||typeof t=="function")for(let s of nr(t))!ar.call(h,s)&&s!==e&&Nt(h,s,{get:()=>t[s],enumerable:!(i=is(t,s))||i.enumerable});return h};var hr=(h,t,e)=>(e=h!=null?rr(or(h)):{},cr(t||!h||!h.__esModule?Nt(e,"default",{value:h,enumerable:!0}):e,h));var _=(h,t,e,i)=>{for(var s=i>1?void 0:i?is(t,e):t,o=h.length-1,c;o>=0;o--)(c=h[o])&&(s=(i?c(t,e,s):c(s))||s);return i&&s&&Nt(t,e,s),s};var Ce,Ut,Kt,rs=zt(()=>{({subtle:Ce}=globalThis.crypto),Ut=class Ut{constructor(t){this.keys=new Map;this.storageKey=t||Ut.DEFAULT_STORAGE_KEY,this.loadKeysFromStorage()}isUnlocked(){return!0}async addKey(t,e){try{let i=await this.parsePrivateKey(e),s=this.generateKeyId(),o={id:s,name:t,publicKey:i.publicKey,privateKey:e,algorithm:"Ed25519",encrypted:i.encrypted,fingerprint:i.fingerprint,createdAt:new Date().toISOString()};return this.keys.set(s,o),this.saveKeysToStorage(),s}catch(i){throw new Error(`Failed to add SSH key: ${i}`)}}removeKey(t){this.keys.delete(t),this.saveKeysToStorage()}listKeys(){return Array.from(this.keys.values()).map(t=>({id:t.id,name:t.name,publicKey:t.publicKey,algorithm:t.algorithm,encrypted:t.encrypted,fingerprint:t.fingerprint,createdAt:t.createdAt}))}async sign(t,e){let i=this.keys.get(t);if(!i)throw new Error("SSH key not found");if(!i.privateKey)throw new Error("Private key not available for signing");try{let s=i.privateKey;if(i.encrypted){let a=await this.promptForPassword(i.name);if(!a)throw new Error("Password required for encrypted key");s=await this.decryptPrivateKey(i.privateKey,a)}let o=await this.importPrivateKey(s,i.algorithm),c=this.base64ToArrayBuffer(e),r=await Ce.sign({name:"Ed25519"},o,c);return{signature:this.arrayBufferToBase64(r),algorithm:i.algorithm}}catch(s){throw new Error(`Failed to sign data: ${s}`)}}async generateKeyPair(t,e){console.log(`\u{1F511} SSH Agent: Starting Ed25519 key generation for "${t}"`);try{let s=await Ce.generateKey({name:"Ed25519"},!0,["sign","verify"]),o=await Ce.exportKey("pkcs8",s.privateKey),c=await Ce.exportKey("raw",s.publicKey),r=this.arrayBufferToPEM(o,"PRIVATE KEY"),a=this.convertEd25519ToSSHPublicKey(c),g=!!e;e&&(r=await this.encryptPrivateKey(r,e));let m=this.generateKeyId(),l={id:m,name:t,publicKey:a,privateKey:r,algorithm:"Ed25519",encrypted:g,fingerprint:await this.generateFingerprint(a),createdAt:new Date().toISOString()};return this.keys.set(m,l),await this.saveKeysToStorage(),console.log(`\u{1F511} SSH Agent: Key "${t}" generated successfully with ID: ${m}`),{keyId:m,privateKeyPEM:r}}catch(i){throw new Error(`Failed to generate key pair: ${i}`)}}getPublicKey(t){let e=this.keys.get(t);return e?e.publicKey:null}getPrivateKey(t){let e=this.keys.get(t);return e?e.privateKey:null}async parsePrivateKey(t){let e=t.includes("BEGIN ENCRYPTED PRIVATE KEY")||t.includes("Proc-Type: 4,ENCRYPTED");if(t.includes("BEGIN PRIVATE KEY")||t.includes("BEGIN ENCRYPTED PRIVATE KEY")){let i="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImported...";return{publicKey:i,algorithm:"Ed25519",fingerprint:await this.generateFingerprint(i),encrypted:e}}throw new Error("Only Ed25519 private keys are supported")}async importPrivateKey(t,e){let i=t.replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----","").replace(/\s/g,""),s=this.base64ToArrayBuffer(i);return Ce.importKey("pkcs8",s,{name:"Ed25519"},!1,["sign"])}convertEd25519ToSSHPublicKey(t){let e=new Uint8Array(t),s=new TextEncoder().encode("ssh-ed25519"),o=new ArrayBuffer(4+s.length+4+e.length),c=new DataView(o),r=new Uint8Array(o),a=0;return c.setUint32(a,s.length,!1),a+=4,r.set(s,a),a+=s.length,c.setUint32(a,e.length,!1),a+=4,r.set(e,a),`ssh-ed25519 ${this.arrayBufferToBase64(o)}`}async generateFingerprint(t){let e=new TextEncoder,i=await Ce.digest("SHA-256",e.encode(t));return this.arrayBufferToBase64(i).substring(0,16)}generateKeyId(){return window.crypto.randomUUID()}arrayBufferToBase64(t){let e=new Uint8Array(t),i="";for(let s=0;s<e.length;s++)i+=String.fromCharCode(e[s]);return btoa(i)}base64ToArrayBuffer(t){let e=atob(t),i=new Uint8Array(e.length);for(let s=0;s<e.length;s++)i[s]=e.charCodeAt(s);return i.buffer}arrayBufferToPEM(t,e){let s=this.arrayBufferToBase64(t).match(/.{1,64}/g)||[];return`-----BEGIN ${e}-----
${s.join(`
`)}
-----END ${e}-----`}async loadKeysFromStorage(){try{let t=localStorage.getItem(this.storageKey);if(t){let e=JSON.parse(t);this.keys.clear(),e.forEach(i=>this.keys.set(i.id,i))}}catch(t){console.error("Failed to load SSH keys from storage:",t)}}async saveKeysToStorage(){try{let t=Array.from(this.keys.values());localStorage.setItem(this.storageKey,JSON.stringify(t))}catch(t){console.error("Failed to save SSH keys to storage:",t)}}async encryptPrivateKey(t,e){let i=new TextEncoder,s=i.encode(t),o=await Ce.importKey("raw",i.encode(e),{name:"PBKDF2"},!1,["deriveKey"]),c=crypto.getRandomValues(new Uint8Array(16)),r=await Ce.deriveKey({name:"PBKDF2",salt:c,iterations:1e5,hash:"SHA-256"},o,{name:"AES-GCM",length:256},!1,["encrypt"]),a=crypto.getRandomValues(new Uint8Array(12)),g=await Ce.encrypt({name:"AES-GCM",iv:a},r,s),m=new Uint8Array(c.length+a.length+g.byteLength);return m.set(c,0),m.set(a,c.length),m.set(new Uint8Array(g),c.length+a.length),`-----BEGIN ENCRYPTED PRIVATE KEY-----
${this.arrayBufferToBase64(m.buffer)}
-----END ENCRYPTED PRIVATE KEY-----`}async decryptPrivateKey(t,e){let i=t.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----","").replace("-----END ENCRYPTED PRIVATE KEY-----","").replace(/\s/g,""),s=this.base64ToArrayBuffer(i),o=new Uint8Array(s),c=o.slice(0,16),r=o.slice(16,28),a=o.slice(28),g=new TextEncoder,m=await Ce.importKey("raw",g.encode(e),{name:"PBKDF2"},!1,["deriveKey"]),l=await Ce.deriveKey({name:"PBKDF2",salt:c,iterations:1e5,hash:"SHA-256"},m,{name:"AES-GCM",length:256},!1,["decrypt"]),v=await Ce.decrypt({name:"AES-GCM",iv:r},l,a);return new TextDecoder().decode(v)}async promptForPassword(t){return window.prompt(`Enter password for SSH key "${t}":`)}};Ut.DEFAULT_STORAGE_KEY="vibetunnel_ssh_keys";Kt=Ut});var ns={};ss(ns,{AuthClient:()=>Wt,authClient:()=>j});var le,Le,Wt,j,Pe=zt(()=>{Z();rs();le=N("auth-client"),Le=class Le{constructor(){this.currentUser=null;this.sshAgent=new Kt,this.loadCurrentUser()}getSSHAgent(){return this.sshAgent}isAuthenticated(){return this.currentUser!==null&&this.isTokenValid()}getCurrentUser(){return this.currentUser}async getCurrentSystemUser(){try{let t=await fetch("/api/auth/current-user");if(t.ok)return(await t.json()).userId;throw new Error("Failed to get current user")}catch(t){throw le.error("Failed to get current system user:",t),t}}async getUserAvatar(t){try{let e=await fetch(`/api/auth/avatar/${t}`);if(e.ok){let i=await e.json();if(i.avatar&&i.avatar.startsWith("data:"))return i.avatar}}catch(e){le.error("Failed to get user avatar:",e)}return"data:image/svg+xml;base64,"+btoa(`
      <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="24" cy="24" r="24" fill="#6B7280"/>
        <circle cx="24" cy="18" r="8" fill="#9CA3AF"/>
        <path d="M8 38c0-8.837 7.163-16 16-16s16 7.163 16 16" fill="#9CA3AF"/>
      </svg>
    `)}async authenticateWithSSHKey(t,e){try{if(!this.sshAgent.isUnlocked())return{success:!1,error:"SSH agent is locked"};let i=await this.createChallenge(t),s=await this.sshAgent.sign(e,i.challenge),o=this.sshAgent.getPublicKey(e);if(!o)return{success:!1,error:"SSH key not found"};let r=await(await fetch("/api/auth/ssh-key",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({challengeId:i.challengeId,publicKey:o,signature:s.signature})})).json();return le.log("\u{1F510} SSH key auth server response:",r),r.success?(le.log("\u2705 SSH key auth successful, setting current user"),this.setCurrentUser({userId:r.userId,token:r.token,authMethod:"ssh-key",loginTime:Date.now()}),le.log("\u{1F464} Current user set:",this.getCurrentUser())):le.log("\u274C SSH key auth failed:",r.error),r}catch(i){return le.error("SSH key authentication failed:",i),{success:!1,error:"SSH key authentication failed"}}}async authenticateWithPassword(t,e){try{let s=await(await fetch("/api/auth/password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({userId:t,password:e})})).json();return s.success&&this.setCurrentUser({userId:s.userId,token:s.token,authMethod:"password",loginTime:Date.now()}),s}catch(i){return le.error("Password authentication failed:",i),{success:!1,error:"Password authentication failed"}}}async authenticate(t){if(le.log("\u{1F680} Starting SSH authentication for user:",t),this.sshAgent.isUnlocked()){let e=this.sshAgent.listKeys();le.log("\u{1F5DD}\uFE0F Found SSH keys:",e.length,e.map(i=>({id:i.id,name:i.name})));for(let i of e)try{le.log(`\u{1F511} Trying SSH key: ${i.name} (${i.id})`);let s=await this.authenticateWithSSHKey(t,i.id);if(le.log(`\u{1F3AF} SSH key ${i.name} result:`,s),s.success)return le.log(`\u2705 Authenticated with SSH key: ${i.name}`),s}catch(s){le.warn(`\u274C SSH key authentication failed for key ${i.name}:`,s)}}else le.log("\u{1F512} SSH agent is locked");return{success:!1,error:"SSH key authentication failed. Password authentication required."}}async logout(){try{this.currentUser?.token&&await fetch("/api/auth/logout",{method:"POST",headers:{Authorization:`Bearer ${this.currentUser.token}`,"Content-Type":"application/json"}})}catch(t){le.warn("Server logout failed:",t)}finally{this.clearCurrentUser()}}getAuthHeader(){return this.currentUser?.token?{Authorization:`Bearer ${this.currentUser.token}`}:{}}async verifyToken(){if(!this.currentUser?.token)return!1;try{return(await(await fetch("/api/auth/verify",{headers:{Authorization:`Bearer ${this.currentUser.token}`}})).json()).valid}catch(t){return le.error("Token verification failed:",t),!1}}async unlockSSHAgent(t){return!0}lockSSHAgent(){}isSSHAgentUnlocked(){return!0}async createChallenge(t){let e=await fetch("/api/auth/challenge",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({userId:t})});if(!e.ok)throw new Error("Failed to create authentication challenge");return e.json()}setCurrentUser(t){this.currentUser=t,this.saveCurrentUser()}clearCurrentUser(){this.currentUser=null,localStorage.removeItem(Le.TOKEN_KEY),localStorage.removeItem(Le.USER_KEY)}saveCurrentUser(){this.currentUser&&(localStorage.setItem(Le.TOKEN_KEY,this.currentUser.token),localStorage.setItem(Le.USER_KEY,JSON.stringify({userId:this.currentUser.userId,authMethod:this.currentUser.authMethod,loginTime:this.currentUser.loginTime})))}loadCurrentUser(){try{let t=localStorage.getItem(Le.TOKEN_KEY),e=localStorage.getItem(Le.USER_KEY);if(t&&e){let i=JSON.parse(e);this.currentUser={token:t,userId:i.userId,authMethod:i.authMethod,loginTime:i.loginTime},this.verifyToken().then(s=>{s||this.clearCurrentUser()})}}catch(t){le.error("Failed to load current user:",t),this.clearCurrentUser()}}isTokenValid(){if(!this.currentUser)return!1;let t=Date.now()-this.currentUser.loginTime,e=24*60*60*1e3;return t<e}};Le.TOKEN_KEY="vibetunnel_auth_token",Le.USER_KEY="vibetunnel_user_data";Wt=Le,j=new Wt});async function pr(){let h=Date.now();if(St&&h-St.timestamp<ur)return St.noAuth;try{let t=await fetch("/api/auth/config");if(t.ok)return St={noAuth:(await t.json()).noAuth===!0,timestamp:h},St.noAuth}catch{}return!1}function fr(h){return h.map(t=>{if(typeof t=="object"&&t!==null)try{return JSON.stringify(t,null,2)}catch{return String(t)}return t})}async function gr(h,t,e){try{let{authClient:i}=await Promise.resolve().then(()=>(Pe(),ns)),s=i.getAuthHeader(),o=await pr();if(!s.Authorization&&!o)return;let c={"Content-Type":"application/json"};s.Authorization&&(c.Authorization=s.Authorization),await fetch("/api/logs/client",{method:"POST",headers:c,body:JSON.stringify({level:h,module:t,args:fr(e)})})}catch{}}function N(h){let t=e=>(...i)=>{e==="debug"&&!dr||(console[e](`[${h}]`,...i),gr(e,h,i))};return{log:t("log"),warn:t("warn"),error:t("error"),debug:t("debug")}}var dr,St,ur,Z=zt(()=>{dr=!1,St=null,ur=6e4});var zs={};ss(zs,{TerminalRenderer:()=>Wi,decodeBinaryBuffer:()=>Ns,renderLineFromBuffer:()=>Os,renderLineFromCells:()=>Fs});function Ds(h){return h.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;")}function Os(h,t,e=-1){let i="",s="",o="",c="",r=()=>{if(s){let a=Ds(s);i+=`<span class="${o}"${c?` style="${c}"`:""}>${a}</span>`,s=""}};for(let a=0;a<h.length;a++){if(h.getCell(a,t),!t)continue;let g=t.getChars()||" ";if(t.getWidth()===0)continue;let{classes:l,style:v}=Kr(t,a===e);(l!==o||v!==c)&&(r(),o=l,c=v),s+=g}return r(),i}function Fs(h,t=-1){let e="",i="",s="",o="",c=()=>{if(i){let a=Ds(i);e+=`<span class="${s}"${o?` style="${o}"`:""}>${a}</span>`,i=""}},r=0;for(let a of h){if(a.width===0)continue;let{classes:g,style:m}=Ur(a,r===t);(g!==s||m!==o)&&(c(),s=g,o=m),i+=a.char,r+=a.width}return c(),e||(e='<span class="terminal-char">&nbsp;</span>'),e}function Kr(h,t){let e="terminal-char",i="";t&&(e+=" cursor");let s=h.getFgColor();if(s!==void 0){if(typeof s=="number"&&s>=0&&s<=255)i+=`color: var(--terminal-color-${s});`;else if(typeof s=="number"&&s>255){let c=s>>16&255,r=s>>8&255,a=s&255;i+=`color: rgb(${c}, ${r}, ${a});`}}let o=h.getBgColor();if(o!==void 0){if(typeof o=="number"&&o>=0&&o<=255)i+=`background-color: var(--terminal-color-${o});`;else if(typeof o=="number"&&o>255){let c=o>>16&255,r=o>>8&255,a=o&255;i+=`background-color: rgb(${c}, ${r}, ${a});`}}if(t&&(i+="background-color: #23d18b;"),h.isBold()&&(e+=" bold"),h.isItalic()&&(e+=" italic"),h.isUnderline()&&(e+=" underline"),h.isDim()&&(e+=" dim"),h.isStrikethrough()&&(e+=" strikethrough"),h.isInverse()){let c=i.match(/color: ([^;]+);/)?.[1],r=i.match(/background-color: ([^;]+);/)?.[1];c&&r?(i=i.replace(/color: [^;]+;/,`color: ${r};`),i=i.replace(/background-color: [^;]+;/,`background-color: ${c};`)):c?(i=i.replace(/color: [^;]+;/,"color: #1e1e1e;"),i+=`background-color: ${c};`):i+="color: #1e1e1e; background-color: #d4d4d4;"}return h.isInvisible()&&(i+="opacity: 0;"),{classes:e,style:i}}function Ur(h,t){let e="terminal-char",i="";if(t&&(e+=" cursor"),h.fg!==void 0)if(h.fg>=0&&h.fg<=255)i+=`color: var(--terminal-color-${h.fg});`;else{let o=h.fg>>16&255,c=h.fg>>8&255,r=h.fg&255;i+=`color: rgb(${o}, ${c}, ${r});`}else i+="color: #d4d4d4;";if(h.bg!==void 0)if(h.bg>=0&&h.bg<=255)i+=`background-color: var(--terminal-color-${h.bg});`;else{let o=h.bg>>16&255,c=h.bg>>8&255,r=h.bg&255;i+=`background-color: rgb(${o}, ${c}, ${r});`}t&&(i+="background-color: #23d18b;");let s=h.attributes||0;if(s&1&&(e+=" bold"),s&2&&(e+=" italic"),s&4&&(e+=" underline"),s&8&&(e+=" dim"),s&64&&(e+=" strikethrough"),s&16){let o=i.match(/color: ([^;]+);/)?.[1],c=i.match(/background-color: ([^;]+);/)?.[1];o&&c?(i=i.replace(/color: [^;]+;/,`color: ${c};`),i=i.replace(/background-color: [^;]+;/,`background-color: ${o};`)):o?(i=i.replace(/color: [^;]+;/,"color: #1e1e1e;"),i+=`background-color: ${o};`):i+="color: #1e1e1e; background-color: #d4d4d4;"}return s&32&&(i+="opacity: 0;"),{classes:e,style:i}}function Ns(h){let t=new DataView(h),e=0,i=t.getUint16(e,!0);if(e+=2,i!==22100)throw new Error("Invalid buffer format");let s=t.getUint8(e++);if(s!==1)throw new Error(`Unsupported buffer version: ${s}`);let o=t.getUint8(e++),c=t.getUint32(e,!0);e+=4;let r=t.getUint32(e,!0);e+=4;let a=t.getInt32(e,!0);e+=4;let g=t.getInt32(e,!0);e+=4;let m=t.getInt32(e,!0);e+=4,e+=4;let l=[],v=new Uint8Array(h);for(;e<v.length;){let f=v[e++];if(f===254){let b=v[e++];for(let w=0;w<b;w++)l.push([{char:" ",width:1}])}else if(f===253){let b=t.getUint16(e,!0);e+=2;let w=[];for(let n=0;n<b;n++){let d=Wr(v,e);e=d.offset,w.push(d.cell)}l.push(w)}}return{cols:c,rows:r,viewportY:a,cursorX:g,cursorY:m,cells:l}}function Wr(h,t){let e=h[t++],i=!!(e&128),s=!!(e&64),o=!!(e&32),c=!!(e&16),r=!!(e&8),a=!!(e&4),g=e&3;if(e===0)return{cell:{char:" ",width:1},offset:t};let m;if(g===0)m=" ";else if(s){let v=h[t++],f=h.slice(t,t+v);m=new TextDecoder().decode(f),t+=v}else m=String.fromCharCode(h[t++]);let l={char:m,width:1};if(i){let v=h[t++];v!==0&&(l.attributes=v),o&&(r?(l.fg=h[t]<<16|h[t+1]<<8|h[t+2],t+=3):l.fg=h[t++]),c&&(a?(l.bg=h[t]<<16|h[t+1]<<8|h[t+2],t+=3):l.bg=h[t++])}return{cell:l,offset:t}}var Wi,qi=zt(()=>{Wi={renderLineFromBuffer:Os,renderLineFromCells:Fs,decodeBinaryBuffer:Ns}});var Ws=lr(Us=>{(()=>{"use strict";var h={349:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.CircularList=void 0;let g=a(460),m=a(844);class l extends m.Disposable{constructor(f){super(),this._maxLength=f,this.onDeleteEmitter=this.register(new g.EventEmitter),this.onDelete=this.onDeleteEmitter.event,this.onInsertEmitter=this.register(new g.EventEmitter),this.onInsert=this.onInsertEmitter.event,this.onTrimEmitter=this.register(new g.EventEmitter),this.onTrim=this.onTrimEmitter.event,this._array=new Array(this._maxLength),this._startIndex=0,this._length=0}get maxLength(){return this._maxLength}set maxLength(f){if(this._maxLength===f)return;let b=new Array(f);for(let w=0;w<Math.min(f,this.length);w++)b[w]=this._array[this._getCyclicIndex(w)];this._array=b,this._maxLength=f,this._startIndex=0}get length(){return this._length}set length(f){if(f>this._length)for(let b=this._length;b<f;b++)this._array[b]=void 0;this._length=f}get(f){return this._array[this._getCyclicIndex(f)]}set(f,b){this._array[this._getCyclicIndex(f)]=b}push(f){this._array[this._getCyclicIndex(this._length)]=f,this._length===this._maxLength?(this._startIndex=++this._startIndex%this._maxLength,this.onTrimEmitter.fire(1)):this._length++}recycle(){if(this._length!==this._maxLength)throw new Error("Can only recycle when the buffer is full");return this._startIndex=++this._startIndex%this._maxLength,this.onTrimEmitter.fire(1),this._array[this._getCyclicIndex(this._length-1)]}get isFull(){return this._length===this._maxLength}pop(){return this._array[this._getCyclicIndex(this._length---1)]}splice(f,b,...w){if(b){for(let n=f;n<this._length-b;n++)this._array[this._getCyclicIndex(n)]=this._array[this._getCyclicIndex(n+b)];this._length-=b,this.onDeleteEmitter.fire({index:f,amount:b})}for(let n=this._length-1;n>=f;n--)this._array[this._getCyclicIndex(n+w.length)]=this._array[this._getCyclicIndex(n)];for(let n=0;n<w.length;n++)this._array[this._getCyclicIndex(f+n)]=w[n];if(w.length&&this.onInsertEmitter.fire({index:f,amount:w.length}),this._length+w.length>this._maxLength){let n=this._length+w.length-this._maxLength;this._startIndex+=n,this._length=this._maxLength,this.onTrimEmitter.fire(n)}else this._length+=w.length}trimStart(f){f>this._length&&(f=this._length),this._startIndex+=f,this._length-=f,this.onTrimEmitter.fire(f)}shiftElements(f,b,w){if(!(b<=0)){if(f<0||f>=this._length)throw new Error("start argument out of range");if(f+w<0)throw new Error("Cannot shift elements in list beyond index 0");if(w>0){for(let d=b-1;d>=0;d--)this.set(f+d+w,this.get(f+d));let n=f+b+w-this._length;if(n>0)for(this._length+=n;this._length>this._maxLength;)this._length--,this._startIndex++,this.onTrimEmitter.fire(1)}else for(let n=0;n<b;n++)this.set(f+n+w,this.get(f+n))}}_getCyclicIndex(f){return(this._startIndex+f)%this._maxLength}}r.CircularList=l},439:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.clone=void 0,r.clone=function a(g,m=5){if(typeof g!="object")return g;let l=Array.isArray(g)?[]:{};for(let v in g)l[v]=m<=1?g[v]:g[v]&&a(g[v],m-1);return l}},969:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.CoreTerminal=void 0;let g=a(844),m=a(585),l=a(348),v=a(866),f=a(744),b=a(302),w=a(83),n=a(460),d=a(753),p=a(480),u=a(994),x=a(282),k=a(435),I=a(981),P=a(660),L=!1;class D extends g.Disposable{get onScroll(){return this._onScrollApi||(this._onScrollApi=this.register(new n.EventEmitter),this._onScroll.event(H=>{this._onScrollApi?.fire(H.position)})),this._onScrollApi.event}get cols(){return this._bufferService.cols}get rows(){return this._bufferService.rows}get buffers(){return this._bufferService.buffers}get options(){return this.optionsService.options}set options(H){for(let R in H)this.optionsService.options[R]=H[R]}constructor(H){super(),this._windowsWrappingHeuristics=this.register(new g.MutableDisposable),this._onBinary=this.register(new n.EventEmitter),this.onBinary=this._onBinary.event,this._onData=this.register(new n.EventEmitter),this.onData=this._onData.event,this._onLineFeed=this.register(new n.EventEmitter),this.onLineFeed=this._onLineFeed.event,this._onResize=this.register(new n.EventEmitter),this.onResize=this._onResize.event,this._onWriteParsed=this.register(new n.EventEmitter),this.onWriteParsed=this._onWriteParsed.event,this._onScroll=this.register(new n.EventEmitter),this._instantiationService=new l.InstantiationService,this.optionsService=this.register(new b.OptionsService(H)),this._instantiationService.setService(m.IOptionsService,this.optionsService),this._bufferService=this.register(this._instantiationService.createInstance(f.BufferService)),this._instantiationService.setService(m.IBufferService,this._bufferService),this._logService=this.register(this._instantiationService.createInstance(v.LogService)),this._instantiationService.setService(m.ILogService,this._logService),this.coreService=this.register(this._instantiationService.createInstance(w.CoreService)),this._instantiationService.setService(m.ICoreService,this.coreService),this.coreMouseService=this.register(this._instantiationService.createInstance(d.CoreMouseService)),this._instantiationService.setService(m.ICoreMouseService,this.coreMouseService),this.unicodeService=this.register(this._instantiationService.createInstance(p.UnicodeService)),this._instantiationService.setService(m.IUnicodeService,this.unicodeService),this._charsetService=this._instantiationService.createInstance(u.CharsetService),this._instantiationService.setService(m.ICharsetService,this._charsetService),this._oscLinkService=this._instantiationService.createInstance(P.OscLinkService),this._instantiationService.setService(m.IOscLinkService,this._oscLinkService),this._inputHandler=this.register(new k.InputHandler(this._bufferService,this._charsetService,this.coreService,this._logService,this.optionsService,this._oscLinkService,this.coreMouseService,this.unicodeService)),this.register((0,n.forwardEvent)(this._inputHandler.onLineFeed,this._onLineFeed)),this.register(this._inputHandler),this.register((0,n.forwardEvent)(this._bufferService.onResize,this._onResize)),this.register((0,n.forwardEvent)(this.coreService.onData,this._onData)),this.register((0,n.forwardEvent)(this.coreService.onBinary,this._onBinary)),this.register(this.coreService.onRequestScrollToBottom(()=>this.scrollToBottom())),this.register(this.coreService.onUserInput(()=>this._writeBuffer.handleUserInput())),this.register(this.optionsService.onMultipleOptionChange(["windowsMode","windowsPty"],()=>this._handleWindowsPtyOptionChange())),this.register(this._bufferService.onScroll(R=>{this._onScroll.fire({position:this._bufferService.buffer.ydisp,source:0}),this._inputHandler.markRangeDirty(this._bufferService.buffer.scrollTop,this._bufferService.buffer.scrollBottom)})),this.register(this._inputHandler.onScroll(R=>{this._onScroll.fire({position:this._bufferService.buffer.ydisp,source:0}),this._inputHandler.markRangeDirty(this._bufferService.buffer.scrollTop,this._bufferService.buffer.scrollBottom)})),this._writeBuffer=this.register(new I.WriteBuffer((R,O)=>this._inputHandler.parse(R,O))),this.register((0,n.forwardEvent)(this._writeBuffer.onWriteParsed,this._onWriteParsed))}write(H,R){this._writeBuffer.write(H,R)}writeSync(H,R){this._logService.logLevel<=m.LogLevelEnum.WARN&&!L&&(this._logService.warn("writeSync is unreliable and will be removed soon."),L=!0),this._writeBuffer.writeSync(H,R)}input(H,R=!0){this.coreService.triggerDataEvent(H,R)}resize(H,R){isNaN(H)||isNaN(R)||(H=Math.max(H,f.MINIMUM_COLS),R=Math.max(R,f.MINIMUM_ROWS),this._bufferService.resize(H,R))}scroll(H,R=!1){this._bufferService.scroll(H,R)}scrollLines(H,R,O){this._bufferService.scrollLines(H,R,O)}scrollPages(H){this.scrollLines(H*(this.rows-1))}scrollToTop(){this.scrollLines(-this._bufferService.buffer.ydisp)}scrollToBottom(){this.scrollLines(this._bufferService.buffer.ybase-this._bufferService.buffer.ydisp)}scrollToLine(H){let R=H-this._bufferService.buffer.ydisp;R!==0&&this.scrollLines(R)}registerEscHandler(H,R){return this._inputHandler.registerEscHandler(H,R)}registerDcsHandler(H,R){return this._inputHandler.registerDcsHandler(H,R)}registerCsiHandler(H,R){return this._inputHandler.registerCsiHandler(H,R)}registerOscHandler(H,R){return this._inputHandler.registerOscHandler(H,R)}_setup(){this._handleWindowsPtyOptionChange()}reset(){this._inputHandler.reset(),this._bufferService.reset(),this._charsetService.reset(),this.coreService.reset(),this.coreMouseService.reset()}_handleWindowsPtyOptionChange(){let H=!1,R=this.optionsService.rawOptions.windowsPty;R&&R.buildNumber!==void 0&&R.buildNumber!==void 0?H=R.backend==="conpty"&&R.buildNumber<21376:this.optionsService.rawOptions.windowsMode&&(H=!0),H?this._enableWindowsWrappingHeuristics():this._windowsWrappingHeuristics.clear()}_enableWindowsWrappingHeuristics(){if(!this._windowsWrappingHeuristics.value){let H=[];H.push(this.onLineFeed(x.updateWindowsModeWrappedState.bind(null,this._bufferService))),H.push(this.registerCsiHandler({final:"H"},()=>((0,x.updateWindowsModeWrappedState)(this._bufferService),!1))),this._windowsWrappingHeuristics.value=(0,g.toDisposable)(()=>{for(let R of H)R.dispose()})}}}r.CoreTerminal=D},460:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.runAndSubscribe=r.forwardEvent=r.EventEmitter=void 0,r.EventEmitter=class{constructor(){this._listeners=[],this._disposed=!1}get event(){return this._event||(this._event=a=>(this._listeners.push(a),{dispose:()=>{if(!this._disposed){for(let m=0;m<this._listeners.length;m++)if(this._listeners[m]===a)return void this._listeners.splice(m,1)}}})),this._event}fire(a,g){let m=[];for(let l=0;l<this._listeners.length;l++)m.push(this._listeners[l]);for(let l=0;l<m.length;l++)m[l].call(void 0,a,g)}dispose(){this.clearListeners(),this._disposed=!0}clearListeners(){this._listeners&&(this._listeners.length=0)}},r.forwardEvent=function(a,g){return a(m=>g.fire(m))},r.runAndSubscribe=function(a,g){return g(void 0),a(m=>g(m))}},435:function(c,r,a){var g=this&&this.__decorate||function(q,y,T,C){var M,B=arguments.length,W=B<3?y:C===null?C=Object.getOwnPropertyDescriptor(y,T):C;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")W=Reflect.decorate(q,y,T,C);else for(var J=q.length-1;J>=0;J--)(M=q[J])&&(W=(B<3?M(W):B>3?M(y,T,W):M(y,T))||W);return B>3&&W&&Object.defineProperty(y,T,W),W},m=this&&this.__param||function(q,y){return function(T,C){y(T,C,q)}};Object.defineProperty(r,"__esModule",{value:!0}),r.InputHandler=r.WindowsOptionsReportType=void 0;let l=a(584),v=a(116),f=a(15),b=a(844),w=a(482),n=a(437),d=a(460),p=a(643),u=a(511),x=a(734),k=a(585),I=a(480),P=a(242),L=a(351),D=a(941),ie={"(":0,")":1,"*":2,"+":3,"-":1,".":2},H=131072;function R(q,y){if(q>24)return y.setWinLines||!1;switch(q){case 1:return!!y.restoreWin;case 2:return!!y.minimizeWin;case 3:return!!y.setWinPosition;case 4:return!!y.setWinSizePixels;case 5:return!!y.raiseWin;case 6:return!!y.lowerWin;case 7:return!!y.refreshWin;case 8:return!!y.setWinSizeChars;case 9:return!!y.maximizeWin;case 10:return!!y.fullscreenWin;case 11:return!!y.getWinState;case 13:return!!y.getWinPosition;case 14:return!!y.getWinSizePixels;case 15:return!!y.getScreenSizePixels;case 16:return!!y.getCellSizePixels;case 18:return!!y.getWinSizeChars;case 19:return!!y.getScreenSizeChars;case 20:return!!y.getIconTitle;case 21:return!!y.getWinTitle;case 22:return!!y.pushTitle;case 23:return!!y.popTitle;case 24:return!!y.setWinLines}return!1}var O;(function(q){q[q.GET_WIN_SIZE_PIXELS=0]="GET_WIN_SIZE_PIXELS",q[q.GET_CELL_SIZE_PIXELS=1]="GET_CELL_SIZE_PIXELS"})(O||(r.WindowsOptionsReportType=O={}));let Ie=0;class Se extends b.Disposable{getAttrData(){return this._curAttrData}constructor(y,T,C,M,B,W,J,se,ke=new f.EscapeSequenceParser){super(),this._bufferService=y,this._charsetService=T,this._coreService=C,this._logService=M,this._optionsService=B,this._oscLinkService=W,this._coreMouseService=J,this._unicodeService=se,this._parser=ke,this._parseBuffer=new Uint32Array(4096),this._stringDecoder=new w.StringToUtf32,this._utf8Decoder=new w.Utf8ToUtf32,this._workCell=new u.CellData,this._windowTitle="",this._iconName="",this._windowTitleStack=[],this._iconNameStack=[],this._curAttrData=n.DEFAULT_ATTR_DATA.clone(),this._eraseAttrDataInternal=n.DEFAULT_ATTR_DATA.clone(),this._onRequestBell=this.register(new d.EventEmitter),this.onRequestBell=this._onRequestBell.event,this._onRequestRefreshRows=this.register(new d.EventEmitter),this.onRequestRefreshRows=this._onRequestRefreshRows.event,this._onRequestReset=this.register(new d.EventEmitter),this.onRequestReset=this._onRequestReset.event,this._onRequestSendFocus=this.register(new d.EventEmitter),this.onRequestSendFocus=this._onRequestSendFocus.event,this._onRequestSyncScrollBar=this.register(new d.EventEmitter),this.onRequestSyncScrollBar=this._onRequestSyncScrollBar.event,this._onRequestWindowsOptionsReport=this.register(new d.EventEmitter),this.onRequestWindowsOptionsReport=this._onRequestWindowsOptionsReport.event,this._onA11yChar=this.register(new d.EventEmitter),this.onA11yChar=this._onA11yChar.event,this._onA11yTab=this.register(new d.EventEmitter),this.onA11yTab=this._onA11yTab.event,this._onCursorMove=this.register(new d.EventEmitter),this.onCursorMove=this._onCursorMove.event,this._onLineFeed=this.register(new d.EventEmitter),this.onLineFeed=this._onLineFeed.event,this._onScroll=this.register(new d.EventEmitter),this.onScroll=this._onScroll.event,this._onTitleChange=this.register(new d.EventEmitter),this.onTitleChange=this._onTitleChange.event,this._onColor=this.register(new d.EventEmitter),this.onColor=this._onColor.event,this._parseStack={paused:!1,cursorStartX:0,cursorStartY:0,decodedLength:0,position:0},this._specialColors=[256,257,258],this.register(this._parser),this._dirtyRowTracker=new G(this._bufferService),this._activeBuffer=this._bufferService.buffer,this.register(this._bufferService.buffers.onBufferActivate(E=>this._activeBuffer=E.activeBuffer)),this._parser.setCsiHandlerFallback((E,X)=>{this._logService.debug("Unknown CSI code: ",{identifier:this._parser.identToString(E),params:X.toArray()})}),this._parser.setEscHandlerFallback(E=>{this._logService.debug("Unknown ESC code: ",{identifier:this._parser.identToString(E)})}),this._parser.setExecuteHandlerFallback(E=>{this._logService.debug("Unknown EXECUTE code: ",{code:E})}),this._parser.setOscHandlerFallback((E,X,U)=>{this._logService.debug("Unknown OSC code: ",{identifier:E,action:X,data:U})}),this._parser.setDcsHandlerFallback((E,X,U)=>{X==="HOOK"&&(U=U.toArray()),this._logService.debug("Unknown DCS code: ",{identifier:this._parser.identToString(E),action:X,payload:U})}),this._parser.setPrintHandler((E,X,U)=>this.print(E,X,U)),this._parser.registerCsiHandler({final:"@"},E=>this.insertChars(E)),this._parser.registerCsiHandler({intermediates:" ",final:"@"},E=>this.scrollLeft(E)),this._parser.registerCsiHandler({final:"A"},E=>this.cursorUp(E)),this._parser.registerCsiHandler({intermediates:" ",final:"A"},E=>this.scrollRight(E)),this._parser.registerCsiHandler({final:"B"},E=>this.cursorDown(E)),this._parser.registerCsiHandler({final:"C"},E=>this.cursorForward(E)),this._parser.registerCsiHandler({final:"D"},E=>this.cursorBackward(E)),this._parser.registerCsiHandler({final:"E"},E=>this.cursorNextLine(E)),this._parser.registerCsiHandler({final:"F"},E=>this.cursorPrecedingLine(E)),this._parser.registerCsiHandler({final:"G"},E=>this.cursorCharAbsolute(E)),this._parser.registerCsiHandler({final:"H"},E=>this.cursorPosition(E)),this._parser.registerCsiHandler({final:"I"},E=>this.cursorForwardTab(E)),this._parser.registerCsiHandler({final:"J"},E=>this.eraseInDisplay(E,!1)),this._parser.registerCsiHandler({prefix:"?",final:"J"},E=>this.eraseInDisplay(E,!0)),this._parser.registerCsiHandler({final:"K"},E=>this.eraseInLine(E,!1)),this._parser.registerCsiHandler({prefix:"?",final:"K"},E=>this.eraseInLine(E,!0)),this._parser.registerCsiHandler({final:"L"},E=>this.insertLines(E)),this._parser.registerCsiHandler({final:"M"},E=>this.deleteLines(E)),this._parser.registerCsiHandler({final:"P"},E=>this.deleteChars(E)),this._parser.registerCsiHandler({final:"S"},E=>this.scrollUp(E)),this._parser.registerCsiHandler({final:"T"},E=>this.scrollDown(E)),this._parser.registerCsiHandler({final:"X"},E=>this.eraseChars(E)),this._parser.registerCsiHandler({final:"Z"},E=>this.cursorBackwardTab(E)),this._parser.registerCsiHandler({final:"`"},E=>this.charPosAbsolute(E)),this._parser.registerCsiHandler({final:"a"},E=>this.hPositionRelative(E)),this._parser.registerCsiHandler({final:"b"},E=>this.repeatPrecedingCharacter(E)),this._parser.registerCsiHandler({final:"c"},E=>this.sendDeviceAttributesPrimary(E)),this._parser.registerCsiHandler({prefix:">",final:"c"},E=>this.sendDeviceAttributesSecondary(E)),this._parser.registerCsiHandler({final:"d"},E=>this.linePosAbsolute(E)),this._parser.registerCsiHandler({final:"e"},E=>this.vPositionRelative(E)),this._parser.registerCsiHandler({final:"f"},E=>this.hVPosition(E)),this._parser.registerCsiHandler({final:"g"},E=>this.tabClear(E)),this._parser.registerCsiHandler({final:"h"},E=>this.setMode(E)),this._parser.registerCsiHandler({prefix:"?",final:"h"},E=>this.setModePrivate(E)),this._parser.registerCsiHandler({final:"l"},E=>this.resetMode(E)),this._parser.registerCsiHandler({prefix:"?",final:"l"},E=>this.resetModePrivate(E)),this._parser.registerCsiHandler({final:"m"},E=>this.charAttributes(E)),this._parser.registerCsiHandler({final:"n"},E=>this.deviceStatus(E)),this._parser.registerCsiHandler({prefix:"?",final:"n"},E=>this.deviceStatusPrivate(E)),this._parser.registerCsiHandler({intermediates:"!",final:"p"},E=>this.softReset(E)),this._parser.registerCsiHandler({intermediates:" ",final:"q"},E=>this.setCursorStyle(E)),this._parser.registerCsiHandler({final:"r"},E=>this.setScrollRegion(E)),this._parser.registerCsiHandler({final:"s"},E=>this.saveCursor(E)),this._parser.registerCsiHandler({final:"t"},E=>this.windowOptions(E)),this._parser.registerCsiHandler({final:"u"},E=>this.restoreCursor(E)),this._parser.registerCsiHandler({intermediates:"'",final:"}"},E=>this.insertColumns(E)),this._parser.registerCsiHandler({intermediates:"'",final:"~"},E=>this.deleteColumns(E)),this._parser.registerCsiHandler({intermediates:'"',final:"q"},E=>this.selectProtected(E)),this._parser.registerCsiHandler({intermediates:"$",final:"p"},E=>this.requestMode(E,!0)),this._parser.registerCsiHandler({prefix:"?",intermediates:"$",final:"p"},E=>this.requestMode(E,!1)),this._parser.setExecuteHandler(l.C0.BEL,()=>this.bell()),this._parser.setExecuteHandler(l.C0.LF,()=>this.lineFeed()),this._parser.setExecuteHandler(l.C0.VT,()=>this.lineFeed()),this._parser.setExecuteHandler(l.C0.FF,()=>this.lineFeed()),this._parser.setExecuteHandler(l.C0.CR,()=>this.carriageReturn()),this._parser.setExecuteHandler(l.C0.BS,()=>this.backspace()),this._parser.setExecuteHandler(l.C0.HT,()=>this.tab()),this._parser.setExecuteHandler(l.C0.SO,()=>this.shiftOut()),this._parser.setExecuteHandler(l.C0.SI,()=>this.shiftIn()),this._parser.setExecuteHandler(l.C1.IND,()=>this.index()),this._parser.setExecuteHandler(l.C1.NEL,()=>this.nextLine()),this._parser.setExecuteHandler(l.C1.HTS,()=>this.tabSet()),this._parser.registerOscHandler(0,new P.OscHandler(E=>(this.setTitle(E),this.setIconName(E),!0))),this._parser.registerOscHandler(1,new P.OscHandler(E=>this.setIconName(E))),this._parser.registerOscHandler(2,new P.OscHandler(E=>this.setTitle(E))),this._parser.registerOscHandler(4,new P.OscHandler(E=>this.setOrReportIndexedColor(E))),this._parser.registerOscHandler(8,new P.OscHandler(E=>this.setHyperlink(E))),this._parser.registerOscHandler(10,new P.OscHandler(E=>this.setOrReportFgColor(E))),this._parser.registerOscHandler(11,new P.OscHandler(E=>this.setOrReportBgColor(E))),this._parser.registerOscHandler(12,new P.OscHandler(E=>this.setOrReportCursorColor(E))),this._parser.registerOscHandler(104,new P.OscHandler(E=>this.restoreIndexedColor(E))),this._parser.registerOscHandler(110,new P.OscHandler(E=>this.restoreFgColor(E))),this._parser.registerOscHandler(111,new P.OscHandler(E=>this.restoreBgColor(E))),this._parser.registerOscHandler(112,new P.OscHandler(E=>this.restoreCursorColor(E))),this._parser.registerEscHandler({final:"7"},()=>this.saveCursor()),this._parser.registerEscHandler({final:"8"},()=>this.restoreCursor()),this._parser.registerEscHandler({final:"D"},()=>this.index()),this._parser.registerEscHandler({final:"E"},()=>this.nextLine()),this._parser.registerEscHandler({final:"H"},()=>this.tabSet()),this._parser.registerEscHandler({final:"M"},()=>this.reverseIndex()),this._parser.registerEscHandler({final:"="},()=>this.keypadApplicationMode()),this._parser.registerEscHandler({final:">"},()=>this.keypadNumericMode()),this._parser.registerEscHandler({final:"c"},()=>this.fullReset()),this._parser.registerEscHandler({final:"n"},()=>this.setgLevel(2)),this._parser.registerEscHandler({final:"o"},()=>this.setgLevel(3)),this._parser.registerEscHandler({final:"|"},()=>this.setgLevel(3)),this._parser.registerEscHandler({final:"}"},()=>this.setgLevel(2)),this._parser.registerEscHandler({final:"~"},()=>this.setgLevel(1)),this._parser.registerEscHandler({intermediates:"%",final:"@"},()=>this.selectDefaultCharset()),this._parser.registerEscHandler({intermediates:"%",final:"G"},()=>this.selectDefaultCharset());for(let E in v.CHARSETS)this._parser.registerEscHandler({intermediates:"(",final:E},()=>this.selectCharset("("+E)),this._parser.registerEscHandler({intermediates:")",final:E},()=>this.selectCharset(")"+E)),this._parser.registerEscHandler({intermediates:"*",final:E},()=>this.selectCharset("*"+E)),this._parser.registerEscHandler({intermediates:"+",final:E},()=>this.selectCharset("+"+E)),this._parser.registerEscHandler({intermediates:"-",final:E},()=>this.selectCharset("-"+E)),this._parser.registerEscHandler({intermediates:".",final:E},()=>this.selectCharset("."+E)),this._parser.registerEscHandler({intermediates:"/",final:E},()=>this.selectCharset("/"+E));this._parser.registerEscHandler({intermediates:"#",final:"8"},()=>this.screenAlignmentPattern()),this._parser.setErrorHandler(E=>(this._logService.error("Parsing error: ",E),E)),this._parser.registerDcsHandler({intermediates:"$",final:"q"},new L.DcsHandler((E,X)=>this.requestStatusString(E,X)))}_preserveStack(y,T,C,M){this._parseStack.paused=!0,this._parseStack.cursorStartX=y,this._parseStack.cursorStartY=T,this._parseStack.decodedLength=C,this._parseStack.position=M}_logSlowResolvingAsync(y){this._logService.logLevel<=k.LogLevelEnum.WARN&&Promise.race([y,new Promise((T,C)=>setTimeout(()=>C("#SLOW_TIMEOUT"),5e3))]).catch(T=>{if(T!=="#SLOW_TIMEOUT")throw T;console.warn("async parser handler taking longer than 5000 ms")})}_getCurrentLinkId(){return this._curAttrData.extended.urlId}parse(y,T){let C,M=this._activeBuffer.x,B=this._activeBuffer.y,W=0,J=this._parseStack.paused;if(J){if(C=this._parser.parse(this._parseBuffer,this._parseStack.decodedLength,T))return this._logSlowResolvingAsync(C),C;M=this._parseStack.cursorStartX,B=this._parseStack.cursorStartY,this._parseStack.paused=!1,y.length>H&&(W=this._parseStack.position+H)}if(this._logService.logLevel<=k.LogLevelEnum.DEBUG&&this._logService.debug("parsing data"+(typeof y=="string"?` "${y}"`:` "${Array.prototype.map.call(y,E=>String.fromCharCode(E)).join("")}"`),typeof y=="string"?y.split("").map(E=>E.charCodeAt(0)):y),this._parseBuffer.length<y.length&&this._parseBuffer.length<H&&(this._parseBuffer=new Uint32Array(Math.min(y.length,H))),J||this._dirtyRowTracker.clearRange(),y.length>H)for(let E=W;E<y.length;E+=H){let X=E+H<y.length?E+H:y.length,U=typeof y=="string"?this._stringDecoder.decode(y.substring(E,X),this._parseBuffer):this._utf8Decoder.decode(y.subarray(E,X),this._parseBuffer);if(C=this._parser.parse(this._parseBuffer,U))return this._preserveStack(M,B,U,E),this._logSlowResolvingAsync(C),C}else if(!J){let E=typeof y=="string"?this._stringDecoder.decode(y,this._parseBuffer):this._utf8Decoder.decode(y,this._parseBuffer);if(C=this._parser.parse(this._parseBuffer,E))return this._preserveStack(M,B,E,0),this._logSlowResolvingAsync(C),C}this._activeBuffer.x===M&&this._activeBuffer.y===B||this._onCursorMove.fire();let se=this._dirtyRowTracker.end+(this._bufferService.buffer.ybase-this._bufferService.buffer.ydisp),ke=this._dirtyRowTracker.start+(this._bufferService.buffer.ybase-this._bufferService.buffer.ydisp);ke<this._bufferService.rows&&this._onRequestRefreshRows.fire(Math.min(ke,this._bufferService.rows-1),Math.min(se,this._bufferService.rows-1))}print(y,T,C){let M,B,W=this._charsetService.charset,J=this._optionsService.rawOptions.screenReaderMode,se=this._bufferService.cols,ke=this._coreService.decPrivateModes.wraparound,E=this._coreService.modes.insertMode,X=this._curAttrData,U=this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y);this._dirtyRowTracker.markDirty(this._activeBuffer.y),this._activeBuffer.x&&C-T>0&&U.getWidth(this._activeBuffer.x-1)===2&&U.setCellFromCodepoint(this._activeBuffer.x-1,0,1,X);let V=this._parser.precedingJoinState;for(let ht=T;ht<C;++ht){if(M=y[ht],M<127&&W){let Qe=W[String.fromCharCode(M)];Qe&&(M=Qe.charCodeAt(0))}let dt=this._unicodeService.charProperties(M,V);B=I.UnicodeService.extractWidth(dt);let Ft=I.UnicodeService.extractShouldJoin(dt),Xe=Ft?I.UnicodeService.extractWidth(V):0;if(V=dt,J&&this._onA11yChar.fire((0,w.stringFromCodePoint)(M)),this._getCurrentLinkId()&&this._oscLinkService.addLineToLink(this._getCurrentLinkId(),this._activeBuffer.ybase+this._activeBuffer.y),this._activeBuffer.x+B-Xe>se){if(ke){let Qe=U,xt=this._activeBuffer.x-Xe;for(this._activeBuffer.x=Xe,this._activeBuffer.y++,this._activeBuffer.y===this._activeBuffer.scrollBottom+1?(this._activeBuffer.y--,this._bufferService.scroll(this._eraseAttrData(),!0)):(this._activeBuffer.y>=this._bufferService.rows&&(this._activeBuffer.y=this._bufferService.rows-1),this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y).isWrapped=!0),U=this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y),Xe>0&&U instanceof n.BufferLine&&U.copyCellsFrom(Qe,xt,0,Xe,!1);xt<se;)Qe.setCellFromCodepoint(xt++,0,1,X)}else if(this._activeBuffer.x=se-1,B===2)continue}if(Ft&&this._activeBuffer.x){let Qe=U.getWidth(this._activeBuffer.x-1)?1:2;U.addCodepointToCell(this._activeBuffer.x-Qe,M,B);for(let xt=B-Xe;--xt>=0;)U.setCellFromCodepoint(this._activeBuffer.x++,0,0,X)}else if(E&&(U.insertCells(this._activeBuffer.x,B-Xe,this._activeBuffer.getNullCell(X)),U.getWidth(se-1)===2&&U.setCellFromCodepoint(se-1,p.NULL_CELL_CODE,p.NULL_CELL_WIDTH,X)),U.setCellFromCodepoint(this._activeBuffer.x++,M,B,X),B>0)for(;--B;)U.setCellFromCodepoint(this._activeBuffer.x++,0,0,X)}this._parser.precedingJoinState=V,this._activeBuffer.x<se&&C-T>0&&U.getWidth(this._activeBuffer.x)===0&&!U.hasContent(this._activeBuffer.x)&&U.setCellFromCodepoint(this._activeBuffer.x,0,1,X),this._dirtyRowTracker.markDirty(this._activeBuffer.y)}registerCsiHandler(y,T){return y.final!=="t"||y.prefix||y.intermediates?this._parser.registerCsiHandler(y,T):this._parser.registerCsiHandler(y,C=>!R(C.params[0],this._optionsService.rawOptions.windowOptions)||T(C))}registerDcsHandler(y,T){return this._parser.registerDcsHandler(y,new L.DcsHandler(T))}registerEscHandler(y,T){return this._parser.registerEscHandler(y,T)}registerOscHandler(y,T){return this._parser.registerOscHandler(y,new P.OscHandler(T))}bell(){return this._onRequestBell.fire(),!0}lineFeed(){return this._dirtyRowTracker.markDirty(this._activeBuffer.y),this._optionsService.rawOptions.convertEol&&(this._activeBuffer.x=0),this._activeBuffer.y++,this._activeBuffer.y===this._activeBuffer.scrollBottom+1?(this._activeBuffer.y--,this._bufferService.scroll(this._eraseAttrData())):this._activeBuffer.y>=this._bufferService.rows?this._activeBuffer.y=this._bufferService.rows-1:this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y).isWrapped=!1,this._activeBuffer.x>=this._bufferService.cols&&this._activeBuffer.x--,this._dirtyRowTracker.markDirty(this._activeBuffer.y),this._onLineFeed.fire(),!0}carriageReturn(){return this._activeBuffer.x=0,!0}backspace(){if(!this._coreService.decPrivateModes.reverseWraparound)return this._restrictCursor(),this._activeBuffer.x>0&&this._activeBuffer.x--,!0;if(this._restrictCursor(this._bufferService.cols),this._activeBuffer.x>0)this._activeBuffer.x--;else if(this._activeBuffer.x===0&&this._activeBuffer.y>this._activeBuffer.scrollTop&&this._activeBuffer.y<=this._activeBuffer.scrollBottom&&this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y)?.isWrapped){this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y).isWrapped=!1,this._activeBuffer.y--,this._activeBuffer.x=this._bufferService.cols-1;let y=this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y);y.hasWidth(this._activeBuffer.x)&&!y.hasContent(this._activeBuffer.x)&&this._activeBuffer.x--}return this._restrictCursor(),!0}tab(){if(this._activeBuffer.x>=this._bufferService.cols)return!0;let y=this._activeBuffer.x;return this._activeBuffer.x=this._activeBuffer.nextStop(),this._optionsService.rawOptions.screenReaderMode&&this._onA11yTab.fire(this._activeBuffer.x-y),!0}shiftOut(){return this._charsetService.setgLevel(1),!0}shiftIn(){return this._charsetService.setgLevel(0),!0}_restrictCursor(y=this._bufferService.cols-1){this._activeBuffer.x=Math.min(y,Math.max(0,this._activeBuffer.x)),this._activeBuffer.y=this._coreService.decPrivateModes.origin?Math.min(this._activeBuffer.scrollBottom,Math.max(this._activeBuffer.scrollTop,this._activeBuffer.y)):Math.min(this._bufferService.rows-1,Math.max(0,this._activeBuffer.y)),this._dirtyRowTracker.markDirty(this._activeBuffer.y)}_setCursor(y,T){this._dirtyRowTracker.markDirty(this._activeBuffer.y),this._coreService.decPrivateModes.origin?(this._activeBuffer.x=y,this._activeBuffer.y=this._activeBuffer.scrollTop+T):(this._activeBuffer.x=y,this._activeBuffer.y=T),this._restrictCursor(),this._dirtyRowTracker.markDirty(this._activeBuffer.y)}_moveCursor(y,T){this._restrictCursor(),this._setCursor(this._activeBuffer.x+y,this._activeBuffer.y+T)}cursorUp(y){let T=this._activeBuffer.y-this._activeBuffer.scrollTop;return T>=0?this._moveCursor(0,-Math.min(T,y.params[0]||1)):this._moveCursor(0,-(y.params[0]||1)),!0}cursorDown(y){let T=this._activeBuffer.scrollBottom-this._activeBuffer.y;return T>=0?this._moveCursor(0,Math.min(T,y.params[0]||1)):this._moveCursor(0,y.params[0]||1),!0}cursorForward(y){return this._moveCursor(y.params[0]||1,0),!0}cursorBackward(y){return this._moveCursor(-(y.params[0]||1),0),!0}cursorNextLine(y){return this.cursorDown(y),this._activeBuffer.x=0,!0}cursorPrecedingLine(y){return this.cursorUp(y),this._activeBuffer.x=0,!0}cursorCharAbsolute(y){return this._setCursor((y.params[0]||1)-1,this._activeBuffer.y),!0}cursorPosition(y){return this._setCursor(y.length>=2?(y.params[1]||1)-1:0,(y.params[0]||1)-1),!0}charPosAbsolute(y){return this._setCursor((y.params[0]||1)-1,this._activeBuffer.y),!0}hPositionRelative(y){return this._moveCursor(y.params[0]||1,0),!0}linePosAbsolute(y){return this._setCursor(this._activeBuffer.x,(y.params[0]||1)-1),!0}vPositionRelative(y){return this._moveCursor(0,y.params[0]||1),!0}hVPosition(y){return this.cursorPosition(y),!0}tabClear(y){let T=y.params[0];return T===0?delete this._activeBuffer.tabs[this._activeBuffer.x]:T===3&&(this._activeBuffer.tabs={}),!0}cursorForwardTab(y){if(this._activeBuffer.x>=this._bufferService.cols)return!0;let T=y.params[0]||1;for(;T--;)this._activeBuffer.x=this._activeBuffer.nextStop();return!0}cursorBackwardTab(y){if(this._activeBuffer.x>=this._bufferService.cols)return!0;let T=y.params[0]||1;for(;T--;)this._activeBuffer.x=this._activeBuffer.prevStop();return!0}selectProtected(y){let T=y.params[0];return T===1&&(this._curAttrData.bg|=536870912),T!==2&&T!==0||(this._curAttrData.bg&=-536870913),!0}_eraseInBufferLine(y,T,C,M=!1,B=!1){let W=this._activeBuffer.lines.get(this._activeBuffer.ybase+y);W.replaceCells(T,C,this._activeBuffer.getNullCell(this._eraseAttrData()),B),M&&(W.isWrapped=!1)}_resetBufferLine(y,T=!1){let C=this._activeBuffer.lines.get(this._activeBuffer.ybase+y);C&&(C.fill(this._activeBuffer.getNullCell(this._eraseAttrData()),T),this._bufferService.buffer.clearMarkers(this._activeBuffer.ybase+y),C.isWrapped=!1)}eraseInDisplay(y,T=!1){let C;switch(this._restrictCursor(this._bufferService.cols),y.params[0]){case 0:for(C=this._activeBuffer.y,this._dirtyRowTracker.markDirty(C),this._eraseInBufferLine(C++,this._activeBuffer.x,this._bufferService.cols,this._activeBuffer.x===0,T);C<this._bufferService.rows;C++)this._resetBufferLine(C,T);this._dirtyRowTracker.markDirty(C);break;case 1:for(C=this._activeBuffer.y,this._dirtyRowTracker.markDirty(C),this._eraseInBufferLine(C,0,this._activeBuffer.x+1,!0,T),this._activeBuffer.x+1>=this._bufferService.cols&&(this._activeBuffer.lines.get(C+1).isWrapped=!1);C--;)this._resetBufferLine(C,T);this._dirtyRowTracker.markDirty(0);break;case 2:for(C=this._bufferService.rows,this._dirtyRowTracker.markDirty(C-1);C--;)this._resetBufferLine(C,T);this._dirtyRowTracker.markDirty(0);break;case 3:let M=this._activeBuffer.lines.length-this._bufferService.rows;M>0&&(this._activeBuffer.lines.trimStart(M),this._activeBuffer.ybase=Math.max(this._activeBuffer.ybase-M,0),this._activeBuffer.ydisp=Math.max(this._activeBuffer.ydisp-M,0),this._onScroll.fire(0))}return!0}eraseInLine(y,T=!1){switch(this._restrictCursor(this._bufferService.cols),y.params[0]){case 0:this._eraseInBufferLine(this._activeBuffer.y,this._activeBuffer.x,this._bufferService.cols,this._activeBuffer.x===0,T);break;case 1:this._eraseInBufferLine(this._activeBuffer.y,0,this._activeBuffer.x+1,!1,T);break;case 2:this._eraseInBufferLine(this._activeBuffer.y,0,this._bufferService.cols,!0,T)}return this._dirtyRowTracker.markDirty(this._activeBuffer.y),!0}insertLines(y){this._restrictCursor();let T=y.params[0]||1;if(this._activeBuffer.y>this._activeBuffer.scrollBottom||this._activeBuffer.y<this._activeBuffer.scrollTop)return!0;let C=this._activeBuffer.ybase+this._activeBuffer.y,M=this._bufferService.rows-1-this._activeBuffer.scrollBottom,B=this._bufferService.rows-1+this._activeBuffer.ybase-M+1;for(;T--;)this._activeBuffer.lines.splice(B-1,1),this._activeBuffer.lines.splice(C,0,this._activeBuffer.getBlankLine(this._eraseAttrData()));return this._dirtyRowTracker.markRangeDirty(this._activeBuffer.y,this._activeBuffer.scrollBottom),this._activeBuffer.x=0,!0}deleteLines(y){this._restrictCursor();let T=y.params[0]||1;if(this._activeBuffer.y>this._activeBuffer.scrollBottom||this._activeBuffer.y<this._activeBuffer.scrollTop)return!0;let C=this._activeBuffer.ybase+this._activeBuffer.y,M;for(M=this._bufferService.rows-1-this._activeBuffer.scrollBottom,M=this._bufferService.rows-1+this._activeBuffer.ybase-M;T--;)this._activeBuffer.lines.splice(C,1),this._activeBuffer.lines.splice(M,0,this._activeBuffer.getBlankLine(this._eraseAttrData()));return this._dirtyRowTracker.markRangeDirty(this._activeBuffer.y,this._activeBuffer.scrollBottom),this._activeBuffer.x=0,!0}insertChars(y){this._restrictCursor();let T=this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y);return T&&(T.insertCells(this._activeBuffer.x,y.params[0]||1,this._activeBuffer.getNullCell(this._eraseAttrData())),this._dirtyRowTracker.markDirty(this._activeBuffer.y)),!0}deleteChars(y){this._restrictCursor();let T=this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y);return T&&(T.deleteCells(this._activeBuffer.x,y.params[0]||1,this._activeBuffer.getNullCell(this._eraseAttrData())),this._dirtyRowTracker.markDirty(this._activeBuffer.y)),!0}scrollUp(y){let T=y.params[0]||1;for(;T--;)this._activeBuffer.lines.splice(this._activeBuffer.ybase+this._activeBuffer.scrollTop,1),this._activeBuffer.lines.splice(this._activeBuffer.ybase+this._activeBuffer.scrollBottom,0,this._activeBuffer.getBlankLine(this._eraseAttrData()));return this._dirtyRowTracker.markRangeDirty(this._activeBuffer.scrollTop,this._activeBuffer.scrollBottom),!0}scrollDown(y){let T=y.params[0]||1;for(;T--;)this._activeBuffer.lines.splice(this._activeBuffer.ybase+this._activeBuffer.scrollBottom,1),this._activeBuffer.lines.splice(this._activeBuffer.ybase+this._activeBuffer.scrollTop,0,this._activeBuffer.getBlankLine(n.DEFAULT_ATTR_DATA));return this._dirtyRowTracker.markRangeDirty(this._activeBuffer.scrollTop,this._activeBuffer.scrollBottom),!0}scrollLeft(y){if(this._activeBuffer.y>this._activeBuffer.scrollBottom||this._activeBuffer.y<this._activeBuffer.scrollTop)return!0;let T=y.params[0]||1;for(let C=this._activeBuffer.scrollTop;C<=this._activeBuffer.scrollBottom;++C){let M=this._activeBuffer.lines.get(this._activeBuffer.ybase+C);M.deleteCells(0,T,this._activeBuffer.getNullCell(this._eraseAttrData())),M.isWrapped=!1}return this._dirtyRowTracker.markRangeDirty(this._activeBuffer.scrollTop,this._activeBuffer.scrollBottom),!0}scrollRight(y){if(this._activeBuffer.y>this._activeBuffer.scrollBottom||this._activeBuffer.y<this._activeBuffer.scrollTop)return!0;let T=y.params[0]||1;for(let C=this._activeBuffer.scrollTop;C<=this._activeBuffer.scrollBottom;++C){let M=this._activeBuffer.lines.get(this._activeBuffer.ybase+C);M.insertCells(0,T,this._activeBuffer.getNullCell(this._eraseAttrData())),M.isWrapped=!1}return this._dirtyRowTracker.markRangeDirty(this._activeBuffer.scrollTop,this._activeBuffer.scrollBottom),!0}insertColumns(y){if(this._activeBuffer.y>this._activeBuffer.scrollBottom||this._activeBuffer.y<this._activeBuffer.scrollTop)return!0;let T=y.params[0]||1;for(let C=this._activeBuffer.scrollTop;C<=this._activeBuffer.scrollBottom;++C){let M=this._activeBuffer.lines.get(this._activeBuffer.ybase+C);M.insertCells(this._activeBuffer.x,T,this._activeBuffer.getNullCell(this._eraseAttrData())),M.isWrapped=!1}return this._dirtyRowTracker.markRangeDirty(this._activeBuffer.scrollTop,this._activeBuffer.scrollBottom),!0}deleteColumns(y){if(this._activeBuffer.y>this._activeBuffer.scrollBottom||this._activeBuffer.y<this._activeBuffer.scrollTop)return!0;let T=y.params[0]||1;for(let C=this._activeBuffer.scrollTop;C<=this._activeBuffer.scrollBottom;++C){let M=this._activeBuffer.lines.get(this._activeBuffer.ybase+C);M.deleteCells(this._activeBuffer.x,T,this._activeBuffer.getNullCell(this._eraseAttrData())),M.isWrapped=!1}return this._dirtyRowTracker.markRangeDirty(this._activeBuffer.scrollTop,this._activeBuffer.scrollBottom),!0}eraseChars(y){this._restrictCursor();let T=this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y);return T&&(T.replaceCells(this._activeBuffer.x,this._activeBuffer.x+(y.params[0]||1),this._activeBuffer.getNullCell(this._eraseAttrData())),this._dirtyRowTracker.markDirty(this._activeBuffer.y)),!0}repeatPrecedingCharacter(y){let T=this._parser.precedingJoinState;if(!T)return!0;let C=y.params[0]||1,M=I.UnicodeService.extractWidth(T),B=this._activeBuffer.x-M,W=this._activeBuffer.lines.get(this._activeBuffer.ybase+this._activeBuffer.y).getString(B),J=new Uint32Array(W.length*C),se=0;for(let E=0;E<W.length;){let X=W.codePointAt(E)||0;J[se++]=X,E+=X>65535?2:1}let ke=se;for(let E=1;E<C;++E)J.copyWithin(ke,0,se),ke+=se;return this.print(J,0,ke),!0}sendDeviceAttributesPrimary(y){return y.params[0]>0||(this._is("xterm")||this._is("rxvt-unicode")||this._is("screen")?this._coreService.triggerDataEvent(l.C0.ESC+"[?1;2c"):this._is("linux")&&this._coreService.triggerDataEvent(l.C0.ESC+"[?6c")),!0}sendDeviceAttributesSecondary(y){return y.params[0]>0||(this._is("xterm")?this._coreService.triggerDataEvent(l.C0.ESC+"[>0;276;0c"):this._is("rxvt-unicode")?this._coreService.triggerDataEvent(l.C0.ESC+"[>85;95;0c"):this._is("linux")?this._coreService.triggerDataEvent(y.params[0]+"c"):this._is("screen")&&this._coreService.triggerDataEvent(l.C0.ESC+"[>83;40003;0c")),!0}_is(y){return(this._optionsService.rawOptions.termName+"").indexOf(y)===0}setMode(y){for(let T=0;T<y.length;T++)switch(y.params[T]){case 4:this._coreService.modes.insertMode=!0;break;case 20:this._optionsService.options.convertEol=!0}return!0}setModePrivate(y){for(let T=0;T<y.length;T++)switch(y.params[T]){case 1:this._coreService.decPrivateModes.applicationCursorKeys=!0;break;case 2:this._charsetService.setgCharset(0,v.DEFAULT_CHARSET),this._charsetService.setgCharset(1,v.DEFAULT_CHARSET),this._charsetService.setgCharset(2,v.DEFAULT_CHARSET),this._charsetService.setgCharset(3,v.DEFAULT_CHARSET);break;case 3:this._optionsService.rawOptions.windowOptions.setWinLines&&(this._bufferService.resize(132,this._bufferService.rows),this._onRequestReset.fire());break;case 6:this._coreService.decPrivateModes.origin=!0,this._setCursor(0,0);break;case 7:this._coreService.decPrivateModes.wraparound=!0;break;case 12:this._optionsService.options.cursorBlink=!0;break;case 45:this._coreService.decPrivateModes.reverseWraparound=!0;break;case 66:this._logService.debug("Serial port requested application keypad."),this._coreService.decPrivateModes.applicationKeypad=!0,this._onRequestSyncScrollBar.fire();break;case 9:this._coreMouseService.activeProtocol="X10";break;case 1e3:this._coreMouseService.activeProtocol="VT200";break;case 1002:this._coreMouseService.activeProtocol="DRAG";break;case 1003:this._coreMouseService.activeProtocol="ANY";break;case 1004:this._coreService.decPrivateModes.sendFocus=!0,this._onRequestSendFocus.fire();break;case 1005:this._logService.debug("DECSET 1005 not supported (see #2507)");break;case 1006:this._coreMouseService.activeEncoding="SGR";break;case 1015:this._logService.debug("DECSET 1015 not supported (see #2507)");break;case 1016:this._coreMouseService.activeEncoding="SGR_PIXELS";break;case 25:this._coreService.isCursorHidden=!1;break;case 1048:this.saveCursor();break;case 1049:this.saveCursor();case 47:case 1047:this._bufferService.buffers.activateAltBuffer(this._eraseAttrData()),this._coreService.isCursorInitialized=!0,this._onRequestRefreshRows.fire(0,this._bufferService.rows-1),this._onRequestSyncScrollBar.fire();break;case 2004:this._coreService.decPrivateModes.bracketedPasteMode=!0}return!0}resetMode(y){for(let T=0;T<y.length;T++)switch(y.params[T]){case 4:this._coreService.modes.insertMode=!1;break;case 20:this._optionsService.options.convertEol=!1}return!0}resetModePrivate(y){for(let T=0;T<y.length;T++)switch(y.params[T]){case 1:this._coreService.decPrivateModes.applicationCursorKeys=!1;break;case 3:this._optionsService.rawOptions.windowOptions.setWinLines&&(this._bufferService.resize(80,this._bufferService.rows),this._onRequestReset.fire());break;case 6:this._coreService.decPrivateModes.origin=!1,this._setCursor(0,0);break;case 7:this._coreService.decPrivateModes.wraparound=!1;break;case 12:this._optionsService.options.cursorBlink=!1;break;case 45:this._coreService.decPrivateModes.reverseWraparound=!1;break;case 66:this._logService.debug("Switching back to normal keypad."),this._coreService.decPrivateModes.applicationKeypad=!1,this._onRequestSyncScrollBar.fire();break;case 9:case 1e3:case 1002:case 1003:this._coreMouseService.activeProtocol="NONE";break;case 1004:this._coreService.decPrivateModes.sendFocus=!1;break;case 1005:this._logService.debug("DECRST 1005 not supported (see #2507)");break;case 1006:case 1016:this._coreMouseService.activeEncoding="DEFAULT";break;case 1015:this._logService.debug("DECRST 1015 not supported (see #2507)");break;case 25:this._coreService.isCursorHidden=!0;break;case 1048:this.restoreCursor();break;case 1049:case 47:case 1047:this._bufferService.buffers.activateNormalBuffer(),y.params[T]===1049&&this.restoreCursor(),this._coreService.isCursorInitialized=!0,this._onRequestRefreshRows.fire(0,this._bufferService.rows-1),this._onRequestSyncScrollBar.fire();break;case 2004:this._coreService.decPrivateModes.bracketedPasteMode=!1}return!0}requestMode(y,T){let C=this._coreService.decPrivateModes,{activeProtocol:M,activeEncoding:B}=this._coreMouseService,W=this._coreService,{buffers:J,cols:se}=this._bufferService,{active:ke,alt:E}=J,X=this._optionsService.rawOptions,U=Ft=>Ft?1:2,V=y.params[0];return ht=V,dt=T?V===2?4:V===4?U(W.modes.insertMode):V===12?3:V===20?U(X.convertEol):0:V===1?U(C.applicationCursorKeys):V===3?X.windowOptions.setWinLines?se===80?2:se===132?1:0:0:V===6?U(C.origin):V===7?U(C.wraparound):V===8?3:V===9?U(M==="X10"):V===12?U(X.cursorBlink):V===25?U(!W.isCursorHidden):V===45?U(C.reverseWraparound):V===66?U(C.applicationKeypad):V===67?4:V===1e3?U(M==="VT200"):V===1002?U(M==="DRAG"):V===1003?U(M==="ANY"):V===1004?U(C.sendFocus):V===1005?4:V===1006?U(B==="SGR"):V===1015?4:V===1016?U(B==="SGR_PIXELS"):V===1048?1:V===47||V===1047||V===1049?U(ke===E):V===2004?U(C.bracketedPasteMode):0,W.triggerDataEvent(`${l.C0.ESC}[${T?"":"?"}${ht};${dt}$y`),!0;var ht,dt}_updateAttrColor(y,T,C,M,B){return T===2?(y|=50331648,y&=-16777216,y|=x.AttributeData.fromColorRGB([C,M,B])):T===5&&(y&=-50331904,y|=33554432|255&C),y}_extractColor(y,T,C){let M=[0,0,-1,0,0,0],B=0,W=0;do{if(M[W+B]=y.params[T+W],y.hasSubParams(T+W)){let J=y.getSubParams(T+W),se=0;do M[1]===5&&(B=1),M[W+se+1+B]=J[se];while(++se<J.length&&se+W+1+B<M.length);break}if(M[1]===5&&W+B>=2||M[1]===2&&W+B>=5)break;M[1]&&(B=1)}while(++W+T<y.length&&W+B<M.length);for(let J=2;J<M.length;++J)M[J]===-1&&(M[J]=0);switch(M[0]){case 38:C.fg=this._updateAttrColor(C.fg,M[1],M[3],M[4],M[5]);break;case 48:C.bg=this._updateAttrColor(C.bg,M[1],M[3],M[4],M[5]);break;case 58:C.extended=C.extended.clone(),C.extended.underlineColor=this._updateAttrColor(C.extended.underlineColor,M[1],M[3],M[4],M[5])}return W}_processUnderline(y,T){T.extended=T.extended.clone(),(!~y||y>5)&&(y=1),T.extended.underlineStyle=y,T.fg|=268435456,y===0&&(T.fg&=-268435457),T.updateExtended()}_processSGR0(y){y.fg=n.DEFAULT_ATTR_DATA.fg,y.bg=n.DEFAULT_ATTR_DATA.bg,y.extended=y.extended.clone(),y.extended.underlineStyle=0,y.extended.underlineColor&=-67108864,y.updateExtended()}charAttributes(y){if(y.length===1&&y.params[0]===0)return this._processSGR0(this._curAttrData),!0;let T=y.length,C,M=this._curAttrData;for(let B=0;B<T;B++)C=y.params[B],C>=30&&C<=37?(M.fg&=-50331904,M.fg|=16777216|C-30):C>=40&&C<=47?(M.bg&=-50331904,M.bg|=16777216|C-40):C>=90&&C<=97?(M.fg&=-50331904,M.fg|=16777224|C-90):C>=100&&C<=107?(M.bg&=-50331904,M.bg|=16777224|C-100):C===0?this._processSGR0(M):C===1?M.fg|=134217728:C===3?M.bg|=67108864:C===4?(M.fg|=268435456,this._processUnderline(y.hasSubParams(B)?y.getSubParams(B)[0]:1,M)):C===5?M.fg|=536870912:C===7?M.fg|=67108864:C===8?M.fg|=1073741824:C===9?M.fg|=2147483648:C===2?M.bg|=134217728:C===21?this._processUnderline(2,M):C===22?(M.fg&=-134217729,M.bg&=-134217729):C===23?M.bg&=-67108865:C===24?(M.fg&=-268435457,this._processUnderline(0,M)):C===25?M.fg&=-536870913:C===27?M.fg&=-67108865:C===28?M.fg&=-1073741825:C===29?M.fg&=2147483647:C===39?(M.fg&=-67108864,M.fg|=16777215&n.DEFAULT_ATTR_DATA.fg):C===49?(M.bg&=-67108864,M.bg|=16777215&n.DEFAULT_ATTR_DATA.bg):C===38||C===48||C===58?B+=this._extractColor(y,B,M):C===53?M.bg|=1073741824:C===55?M.bg&=-1073741825:C===59?(M.extended=M.extended.clone(),M.extended.underlineColor=-1,M.updateExtended()):C===100?(M.fg&=-67108864,M.fg|=16777215&n.DEFAULT_ATTR_DATA.fg,M.bg&=-67108864,M.bg|=16777215&n.DEFAULT_ATTR_DATA.bg):this._logService.debug("Unknown SGR attribute: %d.",C);return!0}deviceStatus(y){switch(y.params[0]){case 5:this._coreService.triggerDataEvent(`${l.C0.ESC}[0n`);break;case 6:let T=this._activeBuffer.y+1,C=this._activeBuffer.x+1;this._coreService.triggerDataEvent(`${l.C0.ESC}[${T};${C}R`)}return!0}deviceStatusPrivate(y){if(y.params[0]===6){let T=this._activeBuffer.y+1,C=this._activeBuffer.x+1;this._coreService.triggerDataEvent(`${l.C0.ESC}[?${T};${C}R`)}return!0}softReset(y){return this._coreService.isCursorHidden=!1,this._onRequestSyncScrollBar.fire(),this._activeBuffer.scrollTop=0,this._activeBuffer.scrollBottom=this._bufferService.rows-1,this._curAttrData=n.DEFAULT_ATTR_DATA.clone(),this._coreService.reset(),this._charsetService.reset(),this._activeBuffer.savedX=0,this._activeBuffer.savedY=this._activeBuffer.ybase,this._activeBuffer.savedCurAttrData.fg=this._curAttrData.fg,this._activeBuffer.savedCurAttrData.bg=this._curAttrData.bg,this._activeBuffer.savedCharset=this._charsetService.charset,this._coreService.decPrivateModes.origin=!1,!0}setCursorStyle(y){let T=y.params[0]||1;switch(T){case 1:case 2:this._optionsService.options.cursorStyle="block";break;case 3:case 4:this._optionsService.options.cursorStyle="underline";break;case 5:case 6:this._optionsService.options.cursorStyle="bar"}let C=T%2==1;return this._optionsService.options.cursorBlink=C,!0}setScrollRegion(y){let T=y.params[0]||1,C;return(y.length<2||(C=y.params[1])>this._bufferService.rows||C===0)&&(C=this._bufferService.rows),C>T&&(this._activeBuffer.scrollTop=T-1,this._activeBuffer.scrollBottom=C-1,this._setCursor(0,0)),!0}windowOptions(y){if(!R(y.params[0],this._optionsService.rawOptions.windowOptions))return!0;let T=y.length>1?y.params[1]:0;switch(y.params[0]){case 14:T!==2&&this._onRequestWindowsOptionsReport.fire(O.GET_WIN_SIZE_PIXELS);break;case 16:this._onRequestWindowsOptionsReport.fire(O.GET_CELL_SIZE_PIXELS);break;case 18:this._bufferService&&this._coreService.triggerDataEvent(`${l.C0.ESC}[8;${this._bufferService.rows};${this._bufferService.cols}t`);break;case 22:T!==0&&T!==2||(this._windowTitleStack.push(this._windowTitle),this._windowTitleStack.length>10&&this._windowTitleStack.shift()),T!==0&&T!==1||(this._iconNameStack.push(this._iconName),this._iconNameStack.length>10&&this._iconNameStack.shift());break;case 23:T!==0&&T!==2||this._windowTitleStack.length&&this.setTitle(this._windowTitleStack.pop()),T!==0&&T!==1||this._iconNameStack.length&&this.setIconName(this._iconNameStack.pop())}return!0}saveCursor(y){return this._activeBuffer.savedX=this._activeBuffer.x,this._activeBuffer.savedY=this._activeBuffer.ybase+this._activeBuffer.y,this._activeBuffer.savedCurAttrData.fg=this._curAttrData.fg,this._activeBuffer.savedCurAttrData.bg=this._curAttrData.bg,this._activeBuffer.savedCharset=this._charsetService.charset,!0}restoreCursor(y){return this._activeBuffer.x=this._activeBuffer.savedX||0,this._activeBuffer.y=Math.max(this._activeBuffer.savedY-this._activeBuffer.ybase,0),this._curAttrData.fg=this._activeBuffer.savedCurAttrData.fg,this._curAttrData.bg=this._activeBuffer.savedCurAttrData.bg,this._charsetService.charset=this._savedCharset,this._activeBuffer.savedCharset&&(this._charsetService.charset=this._activeBuffer.savedCharset),this._restrictCursor(),!0}setTitle(y){return this._windowTitle=y,this._onTitleChange.fire(y),!0}setIconName(y){return this._iconName=y,!0}setOrReportIndexedColor(y){let T=[],C=y.split(";");for(;C.length>1;){let M=C.shift(),B=C.shift();if(/^\d+$/.exec(M)){let W=parseInt(M);if(me(W))if(B==="?")T.push({type:0,index:W});else{let J=(0,D.parseColor)(B);J&&T.push({type:1,index:W,color:J})}}}return T.length&&this._onColor.fire(T),!0}setHyperlink(y){let T=y.split(";");return!(T.length<2)&&(T[1]?this._createHyperlink(T[0],T[1]):!T[0]&&this._finishHyperlink())}_createHyperlink(y,T){this._getCurrentLinkId()&&this._finishHyperlink();let C=y.split(":"),M,B=C.findIndex(W=>W.startsWith("id="));return B!==-1&&(M=C[B].slice(3)||void 0),this._curAttrData.extended=this._curAttrData.extended.clone(),this._curAttrData.extended.urlId=this._oscLinkService.registerLink({id:M,uri:T}),this._curAttrData.updateExtended(),!0}_finishHyperlink(){return this._curAttrData.extended=this._curAttrData.extended.clone(),this._curAttrData.extended.urlId=0,this._curAttrData.updateExtended(),!0}_setOrReportSpecialColor(y,T){let C=y.split(";");for(let M=0;M<C.length&&!(T>=this._specialColors.length);++M,++T)if(C[M]==="?")this._onColor.fire([{type:0,index:this._specialColors[T]}]);else{let B=(0,D.parseColor)(C[M]);B&&this._onColor.fire([{type:1,index:this._specialColors[T],color:B}])}return!0}setOrReportFgColor(y){return this._setOrReportSpecialColor(y,0)}setOrReportBgColor(y){return this._setOrReportSpecialColor(y,1)}setOrReportCursorColor(y){return this._setOrReportSpecialColor(y,2)}restoreIndexedColor(y){if(!y)return this._onColor.fire([{type:2}]),!0;let T=[],C=y.split(";");for(let M=0;M<C.length;++M)if(/^\d+$/.exec(C[M])){let B=parseInt(C[M]);me(B)&&T.push({type:2,index:B})}return T.length&&this._onColor.fire(T),!0}restoreFgColor(y){return this._onColor.fire([{type:2,index:256}]),!0}restoreBgColor(y){return this._onColor.fire([{type:2,index:257}]),!0}restoreCursorColor(y){return this._onColor.fire([{type:2,index:258}]),!0}nextLine(){return this._activeBuffer.x=0,this.index(),!0}keypadApplicationMode(){return this._logService.debug("Serial port requested application keypad."),this._coreService.decPrivateModes.applicationKeypad=!0,this._onRequestSyncScrollBar.fire(),!0}keypadNumericMode(){return this._logService.debug("Switching back to normal keypad."),this._coreService.decPrivateModes.applicationKeypad=!1,this._onRequestSyncScrollBar.fire(),!0}selectDefaultCharset(){return this._charsetService.setgLevel(0),this._charsetService.setgCharset(0,v.DEFAULT_CHARSET),!0}selectCharset(y){return y.length!==2?(this.selectDefaultCharset(),!0):(y[0]==="/"||this._charsetService.setgCharset(ie[y[0]],v.CHARSETS[y[1]]||v.DEFAULT_CHARSET),!0)}index(){return this._restrictCursor(),this._activeBuffer.y++,this._activeBuffer.y===this._activeBuffer.scrollBottom+1?(this._activeBuffer.y--,this._bufferService.scroll(this._eraseAttrData())):this._activeBuffer.y>=this._bufferService.rows&&(this._activeBuffer.y=this._bufferService.rows-1),this._restrictCursor(),!0}tabSet(){return this._activeBuffer.tabs[this._activeBuffer.x]=!0,!0}reverseIndex(){if(this._restrictCursor(),this._activeBuffer.y===this._activeBuffer.scrollTop){let y=this._activeBuffer.scrollBottom-this._activeBuffer.scrollTop;this._activeBuffer.lines.shiftElements(this._activeBuffer.ybase+this._activeBuffer.y,y,1),this._activeBuffer.lines.set(this._activeBuffer.ybase+this._activeBuffer.y,this._activeBuffer.getBlankLine(this._eraseAttrData())),this._dirtyRowTracker.markRangeDirty(this._activeBuffer.scrollTop,this._activeBuffer.scrollBottom)}else this._activeBuffer.y--,this._restrictCursor();return!0}fullReset(){return this._parser.reset(),this._onRequestReset.fire(),!0}reset(){this._curAttrData=n.DEFAULT_ATTR_DATA.clone(),this._eraseAttrDataInternal=n.DEFAULT_ATTR_DATA.clone()}_eraseAttrData(){return this._eraseAttrDataInternal.bg&=-67108864,this._eraseAttrDataInternal.bg|=67108863&this._curAttrData.bg,this._eraseAttrDataInternal}setgLevel(y){return this._charsetService.setgLevel(y),!0}screenAlignmentPattern(){let y=new u.CellData;y.content=4194373,y.fg=this._curAttrData.fg,y.bg=this._curAttrData.bg,this._setCursor(0,0);for(let T=0;T<this._bufferService.rows;++T){let C=this._activeBuffer.ybase+this._activeBuffer.y+T,M=this._activeBuffer.lines.get(C);M&&(M.fill(y),M.isWrapped=!1)}return this._dirtyRowTracker.markAllDirty(),this._setCursor(0,0),!0}requestStatusString(y,T){let C=this._bufferService.buffer,M=this._optionsService.rawOptions;return(B=>(this._coreService.triggerDataEvent(`${l.C0.ESC}${B}${l.C0.ESC}\\`),!0))(y==='"q'?`P1$r${this._curAttrData.isProtected()?1:0}"q`:y==='"p'?'P1$r61;1"p':y==="r"?`P1$r${C.scrollTop+1};${C.scrollBottom+1}r`:y==="m"?"P1$r0m":y===" q"?`P1$r${{block:2,underline:4,bar:6}[M.cursorStyle]-(M.cursorBlink?1:0)} q`:"P0$r")}markRangeDirty(y,T){this._dirtyRowTracker.markRangeDirty(y,T)}}r.InputHandler=Se;let G=class{constructor(q){this._bufferService=q,this.clearRange()}clearRange(){this.start=this._bufferService.buffer.y,this.end=this._bufferService.buffer.y}markDirty(q){q<this.start?this.start=q:q>this.end&&(this.end=q)}markRangeDirty(q,y){q>y&&(Ie=q,q=y,y=Ie),q<this.start&&(this.start=q),y>this.end&&(this.end=y)}markAllDirty(){this.markRangeDirty(0,this._bufferService.rows-1)}};function me(q){return 0<=q&&q<256}G=g([m(0,k.IBufferService)],G)},844:(c,r)=>{function a(g){for(let m of g)m.dispose();g.length=0}Object.defineProperty(r,"__esModule",{value:!0}),r.getDisposeArrayDisposable=r.disposeArray=r.toDisposable=r.MutableDisposable=r.Disposable=void 0,r.Disposable=class{constructor(){this._disposables=[],this._isDisposed=!1}dispose(){this._isDisposed=!0;for(let g of this._disposables)g.dispose();this._disposables.length=0}register(g){return this._disposables.push(g),g}unregister(g){let m=this._disposables.indexOf(g);m!==-1&&this._disposables.splice(m,1)}},r.MutableDisposable=class{constructor(){this._isDisposed=!1}get value(){return this._isDisposed?void 0:this._value}set value(g){this._isDisposed||g===this._value||(this._value?.dispose(),this._value=g)}clear(){this.value=void 0}dispose(){this._isDisposed=!0,this._value?.dispose(),this._value=void 0}},r.toDisposable=function(g){return{dispose:g}},r.disposeArray=a,r.getDisposeArrayDisposable=function(g){return{dispose:()=>a(g)}}},114:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.isChromeOS=r.isLinux=r.isWindows=r.isIphone=r.isIpad=r.isMac=r.getSafariVersion=r.isSafari=r.isLegacyEdge=r.isFirefox=r.isNode=void 0,r.isNode=typeof process<"u"&&"title"in process;let a=r.isNode?"node":navigator.userAgent,g=r.isNode?"node":navigator.platform;r.isFirefox=a.includes("Firefox"),r.isLegacyEdge=a.includes("Edge"),r.isSafari=/^((?!chrome|android).)*safari/i.test(a),r.getSafariVersion=function(){if(!r.isSafari)return 0;let m=a.match(/Version\/(\d+)/);return m===null||m.length<2?0:parseInt(m[1])},r.isMac=["Macintosh","MacIntel","MacPPC","Mac68K"].includes(g),r.isIpad=g==="iPad",r.isIphone=g==="iPhone",r.isWindows=["Windows","Win16","Win32","WinCE"].includes(g),r.isLinux=g.indexOf("Linux")>=0,r.isChromeOS=/\bCrOS\b/.test(a)},226:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.DebouncedIdleTask=r.IdleTaskQueue=r.PriorityTaskQueue=void 0;let g=a(114);class m{constructor(){this._tasks=[],this._i=0}enqueue(f){this._tasks.push(f),this._start()}flush(){for(;this._i<this._tasks.length;)this._tasks[this._i]()||this._i++;this.clear()}clear(){this._idleCallback&&(this._cancelCallback(this._idleCallback),this._idleCallback=void 0),this._i=0,this._tasks.length=0}_start(){this._idleCallback||(this._idleCallback=this._requestCallback(this._process.bind(this)))}_process(f){this._idleCallback=void 0;let b=0,w=0,n=f.timeRemaining(),d=0;for(;this._i<this._tasks.length;){if(b=Date.now(),this._tasks[this._i]()||this._i++,b=Math.max(1,Date.now()-b),w=Math.max(b,w),d=f.timeRemaining(),1.5*w>d)return n-b<-20&&console.warn(`task queue exceeded allotted deadline by ${Math.abs(Math.round(n-b))}ms`),void this._start();n=d}this.clear()}}class l extends m{_requestCallback(f){return setTimeout(()=>f(this._createDeadline(16)))}_cancelCallback(f){clearTimeout(f)}_createDeadline(f){let b=Date.now()+f;return{timeRemaining:()=>Math.max(0,b-Date.now())}}}r.PriorityTaskQueue=l,r.IdleTaskQueue=!g.isNode&&"requestIdleCallback"in window?class extends m{_requestCallback(v){return requestIdleCallback(v)}_cancelCallback(v){cancelIdleCallback(v)}}:l,r.DebouncedIdleTask=class{constructor(){this._queue=new r.IdleTaskQueue}set(v){this._queue.clear(),this._queue.enqueue(v)}flush(){this._queue.flush()}}},282:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.updateWindowsModeWrappedState=void 0;let g=a(643);r.updateWindowsModeWrappedState=function(m){let l=m.buffer.lines.get(m.buffer.ybase+m.buffer.y-1),v=l?.get(m.cols-1),f=m.buffer.lines.get(m.buffer.ybase+m.buffer.y);f&&v&&(f.isWrapped=v[g.CHAR_DATA_CODE_INDEX]!==g.NULL_CELL_CODE&&v[g.CHAR_DATA_CODE_INDEX]!==g.WHITESPACE_CELL_CODE)}},734:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.ExtendedAttrs=r.AttributeData=void 0;class a{constructor(){this.fg=0,this.bg=0,this.extended=new g}static toColorRGB(l){return[l>>>16&255,l>>>8&255,255&l]}static fromColorRGB(l){return(255&l[0])<<16|(255&l[1])<<8|255&l[2]}clone(){let l=new a;return l.fg=this.fg,l.bg=this.bg,l.extended=this.extended.clone(),l}isInverse(){return 67108864&this.fg}isBold(){return 134217728&this.fg}isUnderline(){return this.hasExtendedAttrs()&&this.extended.underlineStyle!==0?1:268435456&this.fg}isBlink(){return 536870912&this.fg}isInvisible(){return 1073741824&this.fg}isItalic(){return 67108864&this.bg}isDim(){return 134217728&this.bg}isStrikethrough(){return 2147483648&this.fg}isProtected(){return 536870912&this.bg}isOverline(){return 1073741824&this.bg}getFgColorMode(){return 50331648&this.fg}getBgColorMode(){return 50331648&this.bg}isFgRGB(){return(50331648&this.fg)==50331648}isBgRGB(){return(50331648&this.bg)==50331648}isFgPalette(){return(50331648&this.fg)==16777216||(50331648&this.fg)==33554432}isBgPalette(){return(50331648&this.bg)==16777216||(50331648&this.bg)==33554432}isFgDefault(){return(50331648&this.fg)==0}isBgDefault(){return(50331648&this.bg)==0}isAttributeDefault(){return this.fg===0&&this.bg===0}getFgColor(){switch(50331648&this.fg){case 16777216:case 33554432:return 255&this.fg;case 50331648:return 16777215&this.fg;default:return-1}}getBgColor(){switch(50331648&this.bg){case 16777216:case 33554432:return 255&this.bg;case 50331648:return 16777215&this.bg;default:return-1}}hasExtendedAttrs(){return 268435456&this.bg}updateExtended(){this.extended.isEmpty()?this.bg&=-268435457:this.bg|=268435456}getUnderlineColor(){if(268435456&this.bg&&~this.extended.underlineColor)switch(50331648&this.extended.underlineColor){case 16777216:case 33554432:return 255&this.extended.underlineColor;case 50331648:return 16777215&this.extended.underlineColor;default:return this.getFgColor()}return this.getFgColor()}getUnderlineColorMode(){return 268435456&this.bg&&~this.extended.underlineColor?50331648&this.extended.underlineColor:this.getFgColorMode()}isUnderlineColorRGB(){return 268435456&this.bg&&~this.extended.underlineColor?(50331648&this.extended.underlineColor)==50331648:this.isFgRGB()}isUnderlineColorPalette(){return 268435456&this.bg&&~this.extended.underlineColor?(50331648&this.extended.underlineColor)==16777216||(50331648&this.extended.underlineColor)==33554432:this.isFgPalette()}isUnderlineColorDefault(){return 268435456&this.bg&&~this.extended.underlineColor?(50331648&this.extended.underlineColor)==0:this.isFgDefault()}getUnderlineStyle(){return 268435456&this.fg?268435456&this.bg?this.extended.underlineStyle:1:0}getUnderlineVariantOffset(){return this.extended.underlineVariantOffset}}r.AttributeData=a;class g{get ext(){return this._urlId?-469762049&this._ext|this.underlineStyle<<26:this._ext}set ext(l){this._ext=l}get underlineStyle(){return this._urlId?5:(469762048&this._ext)>>26}set underlineStyle(l){this._ext&=-469762049,this._ext|=l<<26&469762048}get underlineColor(){return 67108863&this._ext}set underlineColor(l){this._ext&=-67108864,this._ext|=67108863&l}get urlId(){return this._urlId}set urlId(l){this._urlId=l}get underlineVariantOffset(){let l=(3758096384&this._ext)>>29;return l<0?4294967288^l:l}set underlineVariantOffset(l){this._ext&=536870911,this._ext|=l<<29&3758096384}constructor(l=0,v=0){this._ext=0,this._urlId=0,this._ext=l,this._urlId=v}clone(){return new g(this._ext,this._urlId)}isEmpty(){return this.underlineStyle===0&&this._urlId===0}}r.ExtendedAttrs=g},92:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.Buffer=r.MAX_BUFFER_SIZE=void 0;let g=a(349),m=a(226),l=a(734),v=a(437),f=a(634),b=a(511),w=a(643),n=a(863),d=a(116);r.MAX_BUFFER_SIZE=4294967295,r.Buffer=class{constructor(p,u,x){this._hasScrollback=p,this._optionsService=u,this._bufferService=x,this.ydisp=0,this.ybase=0,this.y=0,this.x=0,this.tabs={},this.savedY=0,this.savedX=0,this.savedCurAttrData=v.DEFAULT_ATTR_DATA.clone(),this.savedCharset=d.DEFAULT_CHARSET,this.markers=[],this._nullCell=b.CellData.fromCharData([0,w.NULL_CELL_CHAR,w.NULL_CELL_WIDTH,w.NULL_CELL_CODE]),this._whitespaceCell=b.CellData.fromCharData([0,w.WHITESPACE_CELL_CHAR,w.WHITESPACE_CELL_WIDTH,w.WHITESPACE_CELL_CODE]),this._isClearing=!1,this._memoryCleanupQueue=new m.IdleTaskQueue,this._memoryCleanupPosition=0,this._cols=this._bufferService.cols,this._rows=this._bufferService.rows,this.lines=new g.CircularList(this._getCorrectBufferLength(this._rows)),this.scrollTop=0,this.scrollBottom=this._rows-1,this.setupTabStops()}getNullCell(p){return p?(this._nullCell.fg=p.fg,this._nullCell.bg=p.bg,this._nullCell.extended=p.extended):(this._nullCell.fg=0,this._nullCell.bg=0,this._nullCell.extended=new l.ExtendedAttrs),this._nullCell}getWhitespaceCell(p){return p?(this._whitespaceCell.fg=p.fg,this._whitespaceCell.bg=p.bg,this._whitespaceCell.extended=p.extended):(this._whitespaceCell.fg=0,this._whitespaceCell.bg=0,this._whitespaceCell.extended=new l.ExtendedAttrs),this._whitespaceCell}getBlankLine(p,u){return new v.BufferLine(this._bufferService.cols,this.getNullCell(p),u)}get hasScrollback(){return this._hasScrollback&&this.lines.maxLength>this._rows}get isCursorInViewport(){let p=this.ybase+this.y-this.ydisp;return p>=0&&p<this._rows}_getCorrectBufferLength(p){if(!this._hasScrollback)return p;let u=p+this._optionsService.rawOptions.scrollback;return u>r.MAX_BUFFER_SIZE?r.MAX_BUFFER_SIZE:u}fillViewportRows(p){if(this.lines.length===0){p===void 0&&(p=v.DEFAULT_ATTR_DATA);let u=this._rows;for(;u--;)this.lines.push(this.getBlankLine(p))}}clear(){this.ydisp=0,this.ybase=0,this.y=0,this.x=0,this.lines=new g.CircularList(this._getCorrectBufferLength(this._rows)),this.scrollTop=0,this.scrollBottom=this._rows-1,this.setupTabStops()}resize(p,u){let x=this.getNullCell(v.DEFAULT_ATTR_DATA),k=0,I=this._getCorrectBufferLength(u);if(I>this.lines.maxLength&&(this.lines.maxLength=I),this.lines.length>0){if(this._cols<p)for(let L=0;L<this.lines.length;L++)k+=+this.lines.get(L).resize(p,x);let P=0;if(this._rows<u)for(let L=this._rows;L<u;L++)this.lines.length<u+this.ybase&&(this._optionsService.rawOptions.windowsMode||this._optionsService.rawOptions.windowsPty.backend!==void 0||this._optionsService.rawOptions.windowsPty.buildNumber!==void 0?this.lines.push(new v.BufferLine(p,x)):this.ybase>0&&this.lines.length<=this.ybase+this.y+P+1?(this.ybase--,P++,this.ydisp>0&&this.ydisp--):this.lines.push(new v.BufferLine(p,x)));else for(let L=this._rows;L>u;L--)this.lines.length>u+this.ybase&&(this.lines.length>this.ybase+this.y+1?this.lines.pop():(this.ybase++,this.ydisp++));if(I<this.lines.maxLength){let L=this.lines.length-I;L>0&&(this.lines.trimStart(L),this.ybase=Math.max(this.ybase-L,0),this.ydisp=Math.max(this.ydisp-L,0),this.savedY=Math.max(this.savedY-L,0)),this.lines.maxLength=I}this.x=Math.min(this.x,p-1),this.y=Math.min(this.y,u-1),P&&(this.y+=P),this.savedX=Math.min(this.savedX,p-1),this.scrollTop=0}if(this.scrollBottom=u-1,this._isReflowEnabled&&(this._reflow(p,u),this._cols>p))for(let P=0;P<this.lines.length;P++)k+=+this.lines.get(P).resize(p,x);this._cols=p,this._rows=u,this._memoryCleanupQueue.clear(),k>.1*this.lines.length&&(this._memoryCleanupPosition=0,this._memoryCleanupQueue.enqueue(()=>this._batchedMemoryCleanup()))}_batchedMemoryCleanup(){let p=!0;this._memoryCleanupPosition>=this.lines.length&&(this._memoryCleanupPosition=0,p=!1);let u=0;for(;this._memoryCleanupPosition<this.lines.length;)if(u+=this.lines.get(this._memoryCleanupPosition++).cleanupMemory(),u>100)return!0;return p}get _isReflowEnabled(){let p=this._optionsService.rawOptions.windowsPty;return p&&p.buildNumber?this._hasScrollback&&p.backend==="conpty"&&p.buildNumber>=21376:this._hasScrollback&&!this._optionsService.rawOptions.windowsMode}_reflow(p,u){this._cols!==p&&(p>this._cols?this._reflowLarger(p,u):this._reflowSmaller(p,u))}_reflowLarger(p,u){let x=(0,f.reflowLargerGetLinesToRemove)(this.lines,this._cols,p,this.ybase+this.y,this.getNullCell(v.DEFAULT_ATTR_DATA));if(x.length>0){let k=(0,f.reflowLargerCreateNewLayout)(this.lines,x);(0,f.reflowLargerApplyNewLayout)(this.lines,k.layout),this._reflowLargerAdjustViewport(p,u,k.countRemoved)}}_reflowLargerAdjustViewport(p,u,x){let k=this.getNullCell(v.DEFAULT_ATTR_DATA),I=x;for(;I-- >0;)this.ybase===0?(this.y>0&&this.y--,this.lines.length<u&&this.lines.push(new v.BufferLine(p,k))):(this.ydisp===this.ybase&&this.ydisp--,this.ybase--);this.savedY=Math.max(this.savedY-x,0)}_reflowSmaller(p,u){let x=this.getNullCell(v.DEFAULT_ATTR_DATA),k=[],I=0;for(let P=this.lines.length-1;P>=0;P--){let L=this.lines.get(P);if(!L||!L.isWrapped&&L.getTrimmedLength()<=p)continue;let D=[L];for(;L.isWrapped&&P>0;)L=this.lines.get(--P),D.unshift(L);let ie=this.ybase+this.y;if(ie>=P&&ie<P+D.length)continue;let H=D[D.length-1].getTrimmedLength(),R=(0,f.reflowSmallerGetNewLineLengths)(D,this._cols,p),O=R.length-D.length,Ie;Ie=this.ybase===0&&this.y!==this.lines.length-1?Math.max(0,this.y-this.lines.maxLength+O):Math.max(0,this.lines.length-this.lines.maxLength+O);let Se=[];for(let C=0;C<O;C++){let M=this.getBlankLine(v.DEFAULT_ATTR_DATA,!0);Se.push(M)}Se.length>0&&(k.push({start:P+D.length+I,newLines:Se}),I+=Se.length),D.push(...Se);let G=R.length-1,me=R[G];me===0&&(G--,me=R[G]);let q=D.length-O-1,y=H;for(;q>=0;){let C=Math.min(y,me);if(D[G]===void 0)break;if(D[G].copyCellsFrom(D[q],y-C,me-C,C,!0),me-=C,me===0&&(G--,me=R[G]),y-=C,y===0){q--;let M=Math.max(q,0);y=(0,f.getWrappedLineTrimmedLength)(D,M,this._cols)}}for(let C=0;C<D.length;C++)R[C]<p&&D[C].setCell(R[C],x);let T=O-Ie;for(;T-- >0;)this.ybase===0?this.y<u-1?(this.y++,this.lines.pop()):(this.ybase++,this.ydisp++):this.ybase<Math.min(this.lines.maxLength,this.lines.length+I)-u&&(this.ybase===this.ydisp&&this.ydisp++,this.ybase++);this.savedY=Math.min(this.savedY+O,this.ybase+u-1)}if(k.length>0){let P=[],L=[];for(let G=0;G<this.lines.length;G++)L.push(this.lines.get(G));let D=this.lines.length,ie=D-1,H=0,R=k[H];this.lines.length=Math.min(this.lines.maxLength,this.lines.length+I);let O=0;for(let G=Math.min(this.lines.maxLength-1,D+I-1);G>=0;G--)if(R&&R.start>ie+O){for(let me=R.newLines.length-1;me>=0;me--)this.lines.set(G--,R.newLines[me]);G++,P.push({index:ie+1,amount:R.newLines.length}),O+=R.newLines.length,R=k[++H]}else this.lines.set(G,L[ie--]);let Ie=0;for(let G=P.length-1;G>=0;G--)P[G].index+=Ie,this.lines.onInsertEmitter.fire(P[G]),Ie+=P[G].amount;let Se=Math.max(0,D+I-this.lines.maxLength);Se>0&&this.lines.onTrimEmitter.fire(Se)}}translateBufferLineToString(p,u,x=0,k){let I=this.lines.get(p);return I?I.translateToString(u,x,k):""}getWrappedRangeForLine(p){let u=p,x=p;for(;u>0&&this.lines.get(u).isWrapped;)u--;for(;x+1<this.lines.length&&this.lines.get(x+1).isWrapped;)x++;return{first:u,last:x}}setupTabStops(p){for(p!=null?this.tabs[p]||(p=this.prevStop(p)):(this.tabs={},p=0);p<this._cols;p+=this._optionsService.rawOptions.tabStopWidth)this.tabs[p]=!0}prevStop(p){for(p==null&&(p=this.x);!this.tabs[--p]&&p>0;);return p>=this._cols?this._cols-1:p<0?0:p}nextStop(p){for(p==null&&(p=this.x);!this.tabs[++p]&&p<this._cols;);return p>=this._cols?this._cols-1:p<0?0:p}clearMarkers(p){this._isClearing=!0;for(let u=0;u<this.markers.length;u++)this.markers[u].line===p&&(this.markers[u].dispose(),this.markers.splice(u--,1));this._isClearing=!1}clearAllMarkers(){this._isClearing=!0;for(let p=0;p<this.markers.length;p++)this.markers[p].dispose(),this.markers.splice(p--,1);this._isClearing=!1}addMarker(p){let u=new n.Marker(p);return this.markers.push(u),u.register(this.lines.onTrim(x=>{u.line-=x,u.line<0&&u.dispose()})),u.register(this.lines.onInsert(x=>{u.line>=x.index&&(u.line+=x.amount)})),u.register(this.lines.onDelete(x=>{u.line>=x.index&&u.line<x.index+x.amount&&u.dispose(),u.line>x.index&&(u.line-=x.amount)})),u.register(u.onDispose(()=>this._removeMarker(u))),u}_removeMarker(p){this._isClearing||this.markers.splice(this.markers.indexOf(p),1)}}},437:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.BufferLine=r.DEFAULT_ATTR_DATA=void 0;let g=a(734),m=a(511),l=a(643),v=a(482);r.DEFAULT_ATTR_DATA=Object.freeze(new g.AttributeData);let f=0;class b{constructor(n,d,p=!1){this.isWrapped=p,this._combined={},this._extendedAttrs={},this._data=new Uint32Array(3*n);let u=d||m.CellData.fromCharData([0,l.NULL_CELL_CHAR,l.NULL_CELL_WIDTH,l.NULL_CELL_CODE]);for(let x=0;x<n;++x)this.setCell(x,u);this.length=n}get(n){let d=this._data[3*n+0],p=2097151&d;return[this._data[3*n+1],2097152&d?this._combined[n]:p?(0,v.stringFromCodePoint)(p):"",d>>22,2097152&d?this._combined[n].charCodeAt(this._combined[n].length-1):p]}set(n,d){this._data[3*n+1]=d[l.CHAR_DATA_ATTR_INDEX],d[l.CHAR_DATA_CHAR_INDEX].length>1?(this._combined[n]=d[1],this._data[3*n+0]=2097152|n|d[l.CHAR_DATA_WIDTH_INDEX]<<22):this._data[3*n+0]=d[l.CHAR_DATA_CHAR_INDEX].charCodeAt(0)|d[l.CHAR_DATA_WIDTH_INDEX]<<22}getWidth(n){return this._data[3*n+0]>>22}hasWidth(n){return 12582912&this._data[3*n+0]}getFg(n){return this._data[3*n+1]}getBg(n){return this._data[3*n+2]}hasContent(n){return 4194303&this._data[3*n+0]}getCodePoint(n){let d=this._data[3*n+0];return 2097152&d?this._combined[n].charCodeAt(this._combined[n].length-1):2097151&d}isCombined(n){return 2097152&this._data[3*n+0]}getString(n){let d=this._data[3*n+0];return 2097152&d?this._combined[n]:2097151&d?(0,v.stringFromCodePoint)(2097151&d):""}isProtected(n){return 536870912&this._data[3*n+2]}loadCell(n,d){return f=3*n,d.content=this._data[f+0],d.fg=this._data[f+1],d.bg=this._data[f+2],2097152&d.content&&(d.combinedData=this._combined[n]),268435456&d.bg&&(d.extended=this._extendedAttrs[n]),d}setCell(n,d){2097152&d.content&&(this._combined[n]=d.combinedData),268435456&d.bg&&(this._extendedAttrs[n]=d.extended),this._data[3*n+0]=d.content,this._data[3*n+1]=d.fg,this._data[3*n+2]=d.bg}setCellFromCodepoint(n,d,p,u){268435456&u.bg&&(this._extendedAttrs[n]=u.extended),this._data[3*n+0]=d|p<<22,this._data[3*n+1]=u.fg,this._data[3*n+2]=u.bg}addCodepointToCell(n,d,p){let u=this._data[3*n+0];2097152&u?this._combined[n]+=(0,v.stringFromCodePoint)(d):2097151&u?(this._combined[n]=(0,v.stringFromCodePoint)(2097151&u)+(0,v.stringFromCodePoint)(d),u&=-2097152,u|=2097152):u=d|4194304,p&&(u&=-12582913,u|=p<<22),this._data[3*n+0]=u}insertCells(n,d,p){if((n%=this.length)&&this.getWidth(n-1)===2&&this.setCellFromCodepoint(n-1,0,1,p),d<this.length-n){let u=new m.CellData;for(let x=this.length-n-d-1;x>=0;--x)this.setCell(n+d+x,this.loadCell(n+x,u));for(let x=0;x<d;++x)this.setCell(n+x,p)}else for(let u=n;u<this.length;++u)this.setCell(u,p);this.getWidth(this.length-1)===2&&this.setCellFromCodepoint(this.length-1,0,1,p)}deleteCells(n,d,p){if(n%=this.length,d<this.length-n){let u=new m.CellData;for(let x=0;x<this.length-n-d;++x)this.setCell(n+x,this.loadCell(n+d+x,u));for(let x=this.length-d;x<this.length;++x)this.setCell(x,p)}else for(let u=n;u<this.length;++u)this.setCell(u,p);n&&this.getWidth(n-1)===2&&this.setCellFromCodepoint(n-1,0,1,p),this.getWidth(n)!==0||this.hasContent(n)||this.setCellFromCodepoint(n,0,1,p)}replaceCells(n,d,p,u=!1){if(u)for(n&&this.getWidth(n-1)===2&&!this.isProtected(n-1)&&this.setCellFromCodepoint(n-1,0,1,p),d<this.length&&this.getWidth(d-1)===2&&!this.isProtected(d)&&this.setCellFromCodepoint(d,0,1,p);n<d&&n<this.length;)this.isProtected(n)||this.setCell(n,p),n++;else for(n&&this.getWidth(n-1)===2&&this.setCellFromCodepoint(n-1,0,1,p),d<this.length&&this.getWidth(d-1)===2&&this.setCellFromCodepoint(d,0,1,p);n<d&&n<this.length;)this.setCell(n++,p)}resize(n,d){if(n===this.length)return 4*this._data.length*2<this._data.buffer.byteLength;let p=3*n;if(n>this.length){if(this._data.buffer.byteLength>=4*p)this._data=new Uint32Array(this._data.buffer,0,p);else{let u=new Uint32Array(p);u.set(this._data),this._data=u}for(let u=this.length;u<n;++u)this.setCell(u,d)}else{this._data=this._data.subarray(0,p);let u=Object.keys(this._combined);for(let k=0;k<u.length;k++){let I=parseInt(u[k],10);I>=n&&delete this._combined[I]}let x=Object.keys(this._extendedAttrs);for(let k=0;k<x.length;k++){let I=parseInt(x[k],10);I>=n&&delete this._extendedAttrs[I]}}return this.length=n,4*p*2<this._data.buffer.byteLength}cleanupMemory(){if(4*this._data.length*2<this._data.buffer.byteLength){let n=new Uint32Array(this._data.length);return n.set(this._data),this._data=n,1}return 0}fill(n,d=!1){if(d)for(let p=0;p<this.length;++p)this.isProtected(p)||this.setCell(p,n);else{this._combined={},this._extendedAttrs={};for(let p=0;p<this.length;++p)this.setCell(p,n)}}copyFrom(n){this.length!==n.length?this._data=new Uint32Array(n._data):this._data.set(n._data),this.length=n.length,this._combined={};for(let d in n._combined)this._combined[d]=n._combined[d];this._extendedAttrs={};for(let d in n._extendedAttrs)this._extendedAttrs[d]=n._extendedAttrs[d];this.isWrapped=n.isWrapped}clone(){let n=new b(0);n._data=new Uint32Array(this._data),n.length=this.length;for(let d in this._combined)n._combined[d]=this._combined[d];for(let d in this._extendedAttrs)n._extendedAttrs[d]=this._extendedAttrs[d];return n.isWrapped=this.isWrapped,n}getTrimmedLength(){for(let n=this.length-1;n>=0;--n)if(4194303&this._data[3*n+0])return n+(this._data[3*n+0]>>22);return 0}getNoBgTrimmedLength(){for(let n=this.length-1;n>=0;--n)if(4194303&this._data[3*n+0]||50331648&this._data[3*n+2])return n+(this._data[3*n+0]>>22);return 0}copyCellsFrom(n,d,p,u,x){let k=n._data;if(x)for(let P=u-1;P>=0;P--){for(let L=0;L<3;L++)this._data[3*(p+P)+L]=k[3*(d+P)+L];268435456&k[3*(d+P)+2]&&(this._extendedAttrs[p+P]=n._extendedAttrs[d+P])}else for(let P=0;P<u;P++){for(let L=0;L<3;L++)this._data[3*(p+P)+L]=k[3*(d+P)+L];268435456&k[3*(d+P)+2]&&(this._extendedAttrs[p+P]=n._extendedAttrs[d+P])}let I=Object.keys(n._combined);for(let P=0;P<I.length;P++){let L=parseInt(I[P],10);L>=d&&(this._combined[L-d+p]=n._combined[L])}}translateToString(n,d,p,u){d=d??0,p=p??this.length,n&&(p=Math.min(p,this.getTrimmedLength())),u&&(u.length=0);let x="";for(;d<p;){let k=this._data[3*d+0],I=2097151&k,P=2097152&k?this._combined[d]:I?(0,v.stringFromCodePoint)(I):l.WHITESPACE_CELL_CHAR;if(x+=P,u)for(let L=0;L<P.length;++L)u.push(d);d+=k>>22||1}return u&&u.push(d),x}}r.BufferLine=b},634:(c,r)=>{function a(g,m,l){if(m===g.length-1)return g[m].getTrimmedLength();let v=!g[m].hasContent(l-1)&&g[m].getWidth(l-1)===1,f=g[m+1].getWidth(0)===2;return v&&f?l-1:l}Object.defineProperty(r,"__esModule",{value:!0}),r.getWrappedLineTrimmedLength=r.reflowSmallerGetNewLineLengths=r.reflowLargerApplyNewLayout=r.reflowLargerCreateNewLayout=r.reflowLargerGetLinesToRemove=void 0,r.reflowLargerGetLinesToRemove=function(g,m,l,v,f){let b=[];for(let w=0;w<g.length-1;w++){let n=w,d=g.get(++n);if(!d.isWrapped)continue;let p=[g.get(w)];for(;n<g.length&&d.isWrapped;)p.push(d),d=g.get(++n);if(v>=w&&v<n){w+=p.length-1;continue}let u=0,x=a(p,u,m),k=1,I=0;for(;k<p.length;){let L=a(p,k,m),D=L-I,ie=l-x,H=Math.min(D,ie);p[u].copyCellsFrom(p[k],I,x,H,!1),x+=H,x===l&&(u++,x=0),I+=H,I===L&&(k++,I=0),x===0&&u!==0&&p[u-1].getWidth(l-1)===2&&(p[u].copyCellsFrom(p[u-1],l-1,x++,1,!1),p[u-1].setCell(l-1,f))}p[u].replaceCells(x,l,f);let P=0;for(let L=p.length-1;L>0&&(L>u||p[L].getTrimmedLength()===0);L--)P++;P>0&&(b.push(w+p.length-P),b.push(P)),w+=p.length-1}return b},r.reflowLargerCreateNewLayout=function(g,m){let l=[],v=0,f=m[v],b=0;for(let w=0;w<g.length;w++)if(f===w){let n=m[++v];g.onDeleteEmitter.fire({index:w-b,amount:n}),w+=n-1,b+=n,f=m[++v]}else l.push(w);return{layout:l,countRemoved:b}},r.reflowLargerApplyNewLayout=function(g,m){let l=[];for(let v=0;v<m.length;v++)l.push(g.get(m[v]));for(let v=0;v<l.length;v++)g.set(v,l[v]);g.length=m.length},r.reflowSmallerGetNewLineLengths=function(g,m,l){let v=[],f=g.map((d,p)=>a(g,p,m)).reduce((d,p)=>d+p),b=0,w=0,n=0;for(;n<f;){if(f-n<l){v.push(f-n);break}b+=l;let d=a(g,w,m);b>d&&(b-=d,w++);let p=g[w].getWidth(b-1)===2;p&&b--;let u=p?l-1:l;v.push(u),n+=u}return v},r.getWrappedLineTrimmedLength=a},295:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.BufferSet=void 0;let g=a(460),m=a(844),l=a(92);class v extends m.Disposable{constructor(b,w){super(),this._optionsService=b,this._bufferService=w,this._onBufferActivate=this.register(new g.EventEmitter),this.onBufferActivate=this._onBufferActivate.event,this.reset(),this.register(this._optionsService.onSpecificOptionChange("scrollback",()=>this.resize(this._bufferService.cols,this._bufferService.rows))),this.register(this._optionsService.onSpecificOptionChange("tabStopWidth",()=>this.setupTabStops()))}reset(){this._normal=new l.Buffer(!0,this._optionsService,this._bufferService),this._normal.fillViewportRows(),this._alt=new l.Buffer(!1,this._optionsService,this._bufferService),this._activeBuffer=this._normal,this._onBufferActivate.fire({activeBuffer:this._normal,inactiveBuffer:this._alt}),this.setupTabStops()}get alt(){return this._alt}get active(){return this._activeBuffer}get normal(){return this._normal}activateNormalBuffer(){this._activeBuffer!==this._normal&&(this._normal.x=this._alt.x,this._normal.y=this._alt.y,this._alt.clearAllMarkers(),this._alt.clear(),this._activeBuffer=this._normal,this._onBufferActivate.fire({activeBuffer:this._normal,inactiveBuffer:this._alt}))}activateAltBuffer(b){this._activeBuffer!==this._alt&&(this._alt.fillViewportRows(b),this._alt.x=this._normal.x,this._alt.y=this._normal.y,this._activeBuffer=this._alt,this._onBufferActivate.fire({activeBuffer:this._alt,inactiveBuffer:this._normal}))}resize(b,w){this._normal.resize(b,w),this._alt.resize(b,w),this.setupTabStops(b)}setupTabStops(b){this._normal.setupTabStops(b),this._alt.setupTabStops(b)}}r.BufferSet=v},511:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.CellData=void 0;let g=a(482),m=a(643),l=a(734);class v extends l.AttributeData{constructor(){super(...arguments),this.content=0,this.fg=0,this.bg=0,this.extended=new l.ExtendedAttrs,this.combinedData=""}static fromCharData(b){let w=new v;return w.setFromCharData(b),w}isCombined(){return 2097152&this.content}getWidth(){return this.content>>22}getChars(){return 2097152&this.content?this.combinedData:2097151&this.content?(0,g.stringFromCodePoint)(2097151&this.content):""}getCode(){return this.isCombined()?this.combinedData.charCodeAt(this.combinedData.length-1):2097151&this.content}setFromCharData(b){this.fg=b[m.CHAR_DATA_ATTR_INDEX],this.bg=0;let w=!1;if(b[m.CHAR_DATA_CHAR_INDEX].length>2)w=!0;else if(b[m.CHAR_DATA_CHAR_INDEX].length===2){let n=b[m.CHAR_DATA_CHAR_INDEX].charCodeAt(0);if(55296<=n&&n<=56319){let d=b[m.CHAR_DATA_CHAR_INDEX].charCodeAt(1);56320<=d&&d<=57343?this.content=1024*(n-55296)+d-56320+65536|b[m.CHAR_DATA_WIDTH_INDEX]<<22:w=!0}else w=!0}else this.content=b[m.CHAR_DATA_CHAR_INDEX].charCodeAt(0)|b[m.CHAR_DATA_WIDTH_INDEX]<<22;w&&(this.combinedData=b[m.CHAR_DATA_CHAR_INDEX],this.content=2097152|b[m.CHAR_DATA_WIDTH_INDEX]<<22)}getAsCharData(){return[this.fg,this.getChars(),this.getWidth(),this.getCode()]}}r.CellData=v},643:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.WHITESPACE_CELL_CODE=r.WHITESPACE_CELL_WIDTH=r.WHITESPACE_CELL_CHAR=r.NULL_CELL_CODE=r.NULL_CELL_WIDTH=r.NULL_CELL_CHAR=r.CHAR_DATA_CODE_INDEX=r.CHAR_DATA_WIDTH_INDEX=r.CHAR_DATA_CHAR_INDEX=r.CHAR_DATA_ATTR_INDEX=r.DEFAULT_EXT=r.DEFAULT_ATTR=r.DEFAULT_COLOR=void 0,r.DEFAULT_COLOR=0,r.DEFAULT_ATTR=256|r.DEFAULT_COLOR<<9,r.DEFAULT_EXT=0,r.CHAR_DATA_ATTR_INDEX=0,r.CHAR_DATA_CHAR_INDEX=1,r.CHAR_DATA_WIDTH_INDEX=2,r.CHAR_DATA_CODE_INDEX=3,r.NULL_CELL_CHAR="",r.NULL_CELL_WIDTH=1,r.NULL_CELL_CODE=0,r.WHITESPACE_CELL_CHAR=" ",r.WHITESPACE_CELL_WIDTH=1,r.WHITESPACE_CELL_CODE=32},863:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.Marker=void 0;let g=a(460),m=a(844);class l{get id(){return this._id}constructor(f){this.line=f,this.isDisposed=!1,this._disposables=[],this._id=l._nextId++,this._onDispose=this.register(new g.EventEmitter),this.onDispose=this._onDispose.event}dispose(){this.isDisposed||(this.isDisposed=!0,this.line=-1,this._onDispose.fire(),(0,m.disposeArray)(this._disposables),this._disposables.length=0)}register(f){return this._disposables.push(f),f}}r.Marker=l,l._nextId=1},116:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.DEFAULT_CHARSET=r.CHARSETS=void 0,r.CHARSETS={},r.DEFAULT_CHARSET=r.CHARSETS.B,r.CHARSETS[0]={"`":"\u25C6",a:"\u2592",b:"\u2409",c:"\u240C",d:"\u240D",e:"\u240A",f:"\xB0",g:"\xB1",h:"\u2424",i:"\u240B",j:"\u2518",k:"\u2510",l:"\u250C",m:"\u2514",n:"\u253C",o:"\u23BA",p:"\u23BB",q:"\u2500",r:"\u23BC",s:"\u23BD",t:"\u251C",u:"\u2524",v:"\u2534",w:"\u252C",x:"\u2502",y:"\u2264",z:"\u2265","{":"\u03C0","|":"\u2260","}":"\xA3","~":"\xB7"},r.CHARSETS.A={"#":"\xA3"},r.CHARSETS.B=void 0,r.CHARSETS[4]={"#":"\xA3","@":"\xBE","[":"ij","\\":"\xBD","]":"|","{":"\xA8","|":"f","}":"\xBC","~":"\xB4"},r.CHARSETS.C=r.CHARSETS[5]={"[":"\xC4","\\":"\xD6","]":"\xC5","^":"\xDC","`":"\xE9","{":"\xE4","|":"\xF6","}":"\xE5","~":"\xFC"},r.CHARSETS.R={"#":"\xA3","@":"\xE0","[":"\xB0","\\":"\xE7","]":"\xA7","{":"\xE9","|":"\xF9","}":"\xE8","~":"\xA8"},r.CHARSETS.Q={"@":"\xE0","[":"\xE2","\\":"\xE7","]":"\xEA","^":"\xEE","`":"\xF4","{":"\xE9","|":"\xF9","}":"\xE8","~":"\xFB"},r.CHARSETS.K={"@":"\xA7","[":"\xC4","\\":"\xD6","]":"\xDC","{":"\xE4","|":"\xF6","}":"\xFC","~":"\xDF"},r.CHARSETS.Y={"#":"\xA3","@":"\xA7","[":"\xB0","\\":"\xE7","]":"\xE9","`":"\xF9","{":"\xE0","|":"\xF2","}":"\xE8","~":"\xEC"},r.CHARSETS.E=r.CHARSETS[6]={"@":"\xC4","[":"\xC6","\\":"\xD8","]":"\xC5","^":"\xDC","`":"\xE4","{":"\xE6","|":"\xF8","}":"\xE5","~":"\xFC"},r.CHARSETS.Z={"#":"\xA3","@":"\xA7","[":"\xA1","\\":"\xD1","]":"\xBF","{":"\xB0","|":"\xF1","}":"\xE7"},r.CHARSETS.H=r.CHARSETS[7]={"@":"\xC9","[":"\xC4","\\":"\xD6","]":"\xC5","^":"\xDC","`":"\xE9","{":"\xE4","|":"\xF6","}":"\xE5","~":"\xFC"},r.CHARSETS["="]={"#":"\xF9","@":"\xE0","[":"\xE9","\\":"\xE7","]":"\xEA","^":"\xEE",_:"\xE8","`":"\xF4","{":"\xE4","|":"\xF6","}":"\xFC","~":"\xFB"}},584:(c,r)=>{var a,g,m;Object.defineProperty(r,"__esModule",{value:!0}),r.C1_ESCAPED=r.C1=r.C0=void 0,function(l){l.NUL="\0",l.SOH="",l.STX="",l.ETX="",l.EOT="",l.ENQ="",l.ACK="",l.BEL="\x07",l.BS="\b",l.HT="	",l.LF=`
`,l.VT="\v",l.FF="\f",l.CR="\r",l.SO="",l.SI="",l.DLE="",l.DC1="",l.DC2="",l.DC3="",l.DC4="",l.NAK="",l.SYN="",l.ETB="",l.CAN="",l.EM="",l.SUB="",l.ESC="\x1B",l.FS="",l.GS="",l.RS="",l.US="",l.SP=" ",l.DEL="\x7F"}(a||(r.C0=a={})),function(l){l.PAD="\x80",l.HOP="\x81",l.BPH="\x82",l.NBH="\x83",l.IND="\x84",l.NEL="\x85",l.SSA="\x86",l.ESA="\x87",l.HTS="\x88",l.HTJ="\x89",l.VTS="\x8A",l.PLD="\x8B",l.PLU="\x8C",l.RI="\x8D",l.SS2="\x8E",l.SS3="\x8F",l.DCS="\x90",l.PU1="\x91",l.PU2="\x92",l.STS="\x93",l.CCH="\x94",l.MW="\x95",l.SPA="\x96",l.EPA="\x97",l.SOS="\x98",l.SGCI="\x99",l.SCI="\x9A",l.CSI="\x9B",l.ST="\x9C",l.OSC="\x9D",l.PM="\x9E",l.APC="\x9F"}(g||(r.C1=g={})),function(l){l.ST=`${a.ESC}\\`}(m||(r.C1_ESCAPED=m={}))},482:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.Utf8ToUtf32=r.StringToUtf32=r.utf32ToString=r.stringFromCodePoint=void 0,r.stringFromCodePoint=function(a){return a>65535?(a-=65536,String.fromCharCode(55296+(a>>10))+String.fromCharCode(a%1024+56320)):String.fromCharCode(a)},r.utf32ToString=function(a,g=0,m=a.length){let l="";for(let v=g;v<m;++v){let f=a[v];f>65535?(f-=65536,l+=String.fromCharCode(55296+(f>>10))+String.fromCharCode(f%1024+56320)):l+=String.fromCharCode(f)}return l},r.StringToUtf32=class{constructor(){this._interim=0}clear(){this._interim=0}decode(a,g){let m=a.length;if(!m)return 0;let l=0,v=0;if(this._interim){let f=a.charCodeAt(v++);56320<=f&&f<=57343?g[l++]=1024*(this._interim-55296)+f-56320+65536:(g[l++]=this._interim,g[l++]=f),this._interim=0}for(let f=v;f<m;++f){let b=a.charCodeAt(f);if(55296<=b&&b<=56319){if(++f>=m)return this._interim=b,l;let w=a.charCodeAt(f);56320<=w&&w<=57343?g[l++]=1024*(b-55296)+w-56320+65536:(g[l++]=b,g[l++]=w)}else b!==65279&&(g[l++]=b)}return l}},r.Utf8ToUtf32=class{constructor(){this.interim=new Uint8Array(3)}clear(){this.interim.fill(0)}decode(a,g){let m=a.length;if(!m)return 0;let l,v,f,b,w=0,n=0,d=0;if(this.interim[0]){let x=!1,k=this.interim[0];k&=(224&k)==192?31:(240&k)==224?15:7;let I,P=0;for(;(I=63&this.interim[++P])&&P<4;)k<<=6,k|=I;let L=(224&this.interim[0])==192?2:(240&this.interim[0])==224?3:4,D=L-P;for(;d<D;){if(d>=m)return 0;if(I=a[d++],(192&I)!=128){d--,x=!0;break}this.interim[P++]=I,k<<=6,k|=63&I}x||(L===2?k<128?d--:g[w++]=k:L===3?k<2048||k>=55296&&k<=57343||k===65279||(g[w++]=k):k<65536||k>1114111||(g[w++]=k)),this.interim.fill(0)}let p=m-4,u=d;for(;u<m;){for(;!(!(u<p)||128&(l=a[u])||128&(v=a[u+1])||128&(f=a[u+2])||128&(b=a[u+3]));)g[w++]=l,g[w++]=v,g[w++]=f,g[w++]=b,u+=4;if(l=a[u++],l<128)g[w++]=l;else if((224&l)==192){if(u>=m)return this.interim[0]=l,w;if(v=a[u++],(192&v)!=128){u--;continue}if(n=(31&l)<<6|63&v,n<128){u--;continue}g[w++]=n}else if((240&l)==224){if(u>=m)return this.interim[0]=l,w;if(v=a[u++],(192&v)!=128){u--;continue}if(u>=m)return this.interim[0]=l,this.interim[1]=v,w;if(f=a[u++],(192&f)!=128){u--;continue}if(n=(15&l)<<12|(63&v)<<6|63&f,n<2048||n>=55296&&n<=57343||n===65279)continue;g[w++]=n}else if((248&l)==240){if(u>=m)return this.interim[0]=l,w;if(v=a[u++],(192&v)!=128){u--;continue}if(u>=m)return this.interim[0]=l,this.interim[1]=v,w;if(f=a[u++],(192&f)!=128){u--;continue}if(u>=m)return this.interim[0]=l,this.interim[1]=v,this.interim[2]=f,w;if(b=a[u++],(192&b)!=128){u--;continue}if(n=(7&l)<<18|(63&v)<<12|(63&f)<<6|63&b,n<65536||n>1114111)continue;g[w++]=n}}return w}}},225:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.UnicodeV6=void 0;let g=a(480),m=[[768,879],[1155,1158],[1160,1161],[1425,1469],[1471,1471],[1473,1474],[1476,1477],[1479,1479],[1536,1539],[1552,1557],[1611,1630],[1648,1648],[1750,1764],[1767,1768],[1770,1773],[1807,1807],[1809,1809],[1840,1866],[1958,1968],[2027,2035],[2305,2306],[2364,2364],[2369,2376],[2381,2381],[2385,2388],[2402,2403],[2433,2433],[2492,2492],[2497,2500],[2509,2509],[2530,2531],[2561,2562],[2620,2620],[2625,2626],[2631,2632],[2635,2637],[2672,2673],[2689,2690],[2748,2748],[2753,2757],[2759,2760],[2765,2765],[2786,2787],[2817,2817],[2876,2876],[2879,2879],[2881,2883],[2893,2893],[2902,2902],[2946,2946],[3008,3008],[3021,3021],[3134,3136],[3142,3144],[3146,3149],[3157,3158],[3260,3260],[3263,3263],[3270,3270],[3276,3277],[3298,3299],[3393,3395],[3405,3405],[3530,3530],[3538,3540],[3542,3542],[3633,3633],[3636,3642],[3655,3662],[3761,3761],[3764,3769],[3771,3772],[3784,3789],[3864,3865],[3893,3893],[3895,3895],[3897,3897],[3953,3966],[3968,3972],[3974,3975],[3984,3991],[3993,4028],[4038,4038],[4141,4144],[4146,4146],[4150,4151],[4153,4153],[4184,4185],[4448,4607],[4959,4959],[5906,5908],[5938,5940],[5970,5971],[6002,6003],[6068,6069],[6071,6077],[6086,6086],[6089,6099],[6109,6109],[6155,6157],[6313,6313],[6432,6434],[6439,6440],[6450,6450],[6457,6459],[6679,6680],[6912,6915],[6964,6964],[6966,6970],[6972,6972],[6978,6978],[7019,7027],[7616,7626],[7678,7679],[8203,8207],[8234,8238],[8288,8291],[8298,8303],[8400,8431],[12330,12335],[12441,12442],[43014,43014],[43019,43019],[43045,43046],[64286,64286],[65024,65039],[65056,65059],[65279,65279],[65529,65531]],l=[[68097,68099],[68101,68102],[68108,68111],[68152,68154],[68159,68159],[119143,119145],[119155,119170],[119173,119179],[119210,119213],[119362,119364],[917505,917505],[917536,917631],[917760,917999]],v;r.UnicodeV6=class{constructor(){if(this.version="6",!v){v=new Uint8Array(65536),v.fill(1),v[0]=0,v.fill(0,1,32),v.fill(0,127,160),v.fill(2,4352,4448),v[9001]=2,v[9002]=2,v.fill(2,11904,42192),v[12351]=1,v.fill(2,44032,55204),v.fill(2,63744,64256),v.fill(2,65040,65050),v.fill(2,65072,65136),v.fill(2,65280,65377),v.fill(2,65504,65511);for(let f=0;f<m.length;++f)v.fill(0,m[f][0],m[f][1]+1)}}wcwidth(f){return f<32?0:f<127?1:f<65536?v[f]:function(b,w){let n,d=0,p=w.length-1;if(b<w[0][0]||b>w[p][1])return!1;for(;p>=d;)if(n=d+p>>1,b>w[n][1])d=n+1;else{if(!(b<w[n][0]))return!0;p=n-1}return!1}(f,l)?0:f>=131072&&f<=196605||f>=196608&&f<=262141?2:1}charProperties(f,b){let w=this.wcwidth(f),n=w===0&&b!==0;if(n){let d=g.UnicodeService.extractWidth(b);d===0?n=!1:d>w&&(w=d)}return g.UnicodeService.createPropertyValue(0,w,n)}}},981:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.WriteBuffer=void 0;let g=a(460),m=a(844);class l extends m.Disposable{constructor(f){super(),this._action=f,this._writeBuffer=[],this._callbacks=[],this._pendingData=0,this._bufferOffset=0,this._isSyncWriting=!1,this._syncCalls=0,this._didUserInput=!1,this._onWriteParsed=this.register(new g.EventEmitter),this.onWriteParsed=this._onWriteParsed.event}handleUserInput(){this._didUserInput=!0}writeSync(f,b){if(b!==void 0&&this._syncCalls>b)return void(this._syncCalls=0);if(this._pendingData+=f.length,this._writeBuffer.push(f),this._callbacks.push(void 0),this._syncCalls++,this._isSyncWriting)return;let w;for(this._isSyncWriting=!0;w=this._writeBuffer.shift();){this._action(w);let n=this._callbacks.shift();n&&n()}this._pendingData=0,this._bufferOffset=2147483647,this._isSyncWriting=!1,this._syncCalls=0}write(f,b){if(this._pendingData>5e7)throw new Error("write data discarded, use flow control to avoid losing data");if(!this._writeBuffer.length){if(this._bufferOffset=0,this._didUserInput)return this._didUserInput=!1,this._pendingData+=f.length,this._writeBuffer.push(f),this._callbacks.push(b),void this._innerWrite();setTimeout(()=>this._innerWrite())}this._pendingData+=f.length,this._writeBuffer.push(f),this._callbacks.push(b)}_innerWrite(f=0,b=!0){let w=f||Date.now();for(;this._writeBuffer.length>this._bufferOffset;){let n=this._writeBuffer[this._bufferOffset],d=this._action(n,b);if(d){let u=x=>Date.now()-w>=12?setTimeout(()=>this._innerWrite(0,x)):this._innerWrite(w,x);return void d.catch(x=>(queueMicrotask(()=>{throw x}),Promise.resolve(!1))).then(u)}let p=this._callbacks[this._bufferOffset];if(p&&p(),this._bufferOffset++,this._pendingData-=n.length,Date.now()-w>=12)break}this._writeBuffer.length>this._bufferOffset?(this._bufferOffset>50&&(this._writeBuffer=this._writeBuffer.slice(this._bufferOffset),this._callbacks=this._callbacks.slice(this._bufferOffset),this._bufferOffset=0),setTimeout(()=>this._innerWrite())):(this._writeBuffer.length=0,this._callbacks.length=0,this._pendingData=0,this._bufferOffset=0),this._onWriteParsed.fire()}}r.WriteBuffer=l},941:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.toRgbString=r.parseColor=void 0;let a=/^([\da-f])\/([\da-f])\/([\da-f])$|^([\da-f]{2})\/([\da-f]{2})\/([\da-f]{2})$|^([\da-f]{3})\/([\da-f]{3})\/([\da-f]{3})$|^([\da-f]{4})\/([\da-f]{4})\/([\da-f]{4})$/,g=/^[\da-f]+$/;function m(l,v){let f=l.toString(16),b=f.length<2?"0"+f:f;switch(v){case 4:return f[0];case 8:return b;case 12:return(b+b).slice(0,3);default:return b+b}}r.parseColor=function(l){if(!l)return;let v=l.toLowerCase();if(v.indexOf("rgb:")===0){v=v.slice(4);let f=a.exec(v);if(f){let b=f[1]?15:f[4]?255:f[7]?4095:65535;return[Math.round(parseInt(f[1]||f[4]||f[7]||f[10],16)/b*255),Math.round(parseInt(f[2]||f[5]||f[8]||f[11],16)/b*255),Math.round(parseInt(f[3]||f[6]||f[9]||f[12],16)/b*255)]}}else if(v.indexOf("#")===0&&(v=v.slice(1),g.exec(v)&&[3,6,9,12].includes(v.length))){let f=v.length/3,b=[0,0,0];for(let w=0;w<3;++w){let n=parseInt(v.slice(f*w,f*w+f),16);b[w]=f===1?n<<4:f===2?n:f===3?n>>4:n>>8}return b}},r.toRgbString=function(l,v=16){let[f,b,w]=l;return`rgb:${m(f,v)}/${m(b,v)}/${m(w,v)}`}},770:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.PAYLOAD_LIMIT=void 0,r.PAYLOAD_LIMIT=1e7},351:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.DcsHandler=r.DcsParser=void 0;let g=a(482),m=a(742),l=a(770),v=[];r.DcsParser=class{constructor(){this._handlers=Object.create(null),this._active=v,this._ident=0,this._handlerFb=()=>{},this._stack={paused:!1,loopPosition:0,fallThrough:!1}}dispose(){this._handlers=Object.create(null),this._handlerFb=()=>{},this._active=v}registerHandler(b,w){this._handlers[b]===void 0&&(this._handlers[b]=[]);let n=this._handlers[b];return n.push(w),{dispose:()=>{let d=n.indexOf(w);d!==-1&&n.splice(d,1)}}}clearHandler(b){this._handlers[b]&&delete this._handlers[b]}setHandlerFallback(b){this._handlerFb=b}reset(){if(this._active.length)for(let b=this._stack.paused?this._stack.loopPosition-1:this._active.length-1;b>=0;--b)this._active[b].unhook(!1);this._stack.paused=!1,this._active=v,this._ident=0}hook(b,w){if(this.reset(),this._ident=b,this._active=this._handlers[b]||v,this._active.length)for(let n=this._active.length-1;n>=0;n--)this._active[n].hook(w);else this._handlerFb(this._ident,"HOOK",w)}put(b,w,n){if(this._active.length)for(let d=this._active.length-1;d>=0;d--)this._active[d].put(b,w,n);else this._handlerFb(this._ident,"PUT",(0,g.utf32ToString)(b,w,n))}unhook(b,w=!0){if(this._active.length){let n=!1,d=this._active.length-1,p=!1;if(this._stack.paused&&(d=this._stack.loopPosition-1,n=w,p=this._stack.fallThrough,this._stack.paused=!1),!p&&n===!1){for(;d>=0&&(n=this._active[d].unhook(b),n!==!0);d--)if(n instanceof Promise)return this._stack.paused=!0,this._stack.loopPosition=d,this._stack.fallThrough=!1,n;d--}for(;d>=0;d--)if(n=this._active[d].unhook(!1),n instanceof Promise)return this._stack.paused=!0,this._stack.loopPosition=d,this._stack.fallThrough=!0,n}else this._handlerFb(this._ident,"UNHOOK",b);this._active=v,this._ident=0}};let f=new m.Params;f.addParam(0),r.DcsHandler=class{constructor(b){this._handler=b,this._data="",this._params=f,this._hitLimit=!1}hook(b){this._params=b.length>1||b.params[0]?b.clone():f,this._data="",this._hitLimit=!1}put(b,w,n){this._hitLimit||(this._data+=(0,g.utf32ToString)(b,w,n),this._data.length>l.PAYLOAD_LIMIT&&(this._data="",this._hitLimit=!0))}unhook(b){let w=!1;if(this._hitLimit)w=!1;else if(b&&(w=this._handler(this._data,this._params),w instanceof Promise))return w.then(n=>(this._params=f,this._data="",this._hitLimit=!1,n));return this._params=f,this._data="",this._hitLimit=!1,w}}},15:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.EscapeSequenceParser=r.VT500_TRANSITION_TABLE=r.TransitionTable=void 0;let g=a(844),m=a(742),l=a(242),v=a(351);class f{constructor(d){this.table=new Uint8Array(d)}setDefault(d,p){this.table.fill(d<<4|p)}add(d,p,u,x){this.table[p<<8|d]=u<<4|x}addMany(d,p,u,x){for(let k=0;k<d.length;k++)this.table[p<<8|d[k]]=u<<4|x}}r.TransitionTable=f;let b=160;r.VT500_TRANSITION_TABLE=function(){let n=new f(4095),d=Array.apply(null,Array(256)).map((P,L)=>L),p=(P,L)=>d.slice(P,L),u=p(32,127),x=p(0,24);x.push(25),x.push.apply(x,p(28,32));let k=p(0,14),I;for(I in n.setDefault(1,0),n.addMany(u,0,2,0),k)n.addMany([24,26,153,154],I,3,0),n.addMany(p(128,144),I,3,0),n.addMany(p(144,152),I,3,0),n.add(156,I,0,0),n.add(27,I,11,1),n.add(157,I,4,8),n.addMany([152,158,159],I,0,7),n.add(155,I,11,3),n.add(144,I,11,9);return n.addMany(x,0,3,0),n.addMany(x,1,3,1),n.add(127,1,0,1),n.addMany(x,8,0,8),n.addMany(x,3,3,3),n.add(127,3,0,3),n.addMany(x,4,3,4),n.add(127,4,0,4),n.addMany(x,6,3,6),n.addMany(x,5,3,5),n.add(127,5,0,5),n.addMany(x,2,3,2),n.add(127,2,0,2),n.add(93,1,4,8),n.addMany(u,8,5,8),n.add(127,8,5,8),n.addMany([156,27,24,26,7],8,6,0),n.addMany(p(28,32),8,0,8),n.addMany([88,94,95],1,0,7),n.addMany(u,7,0,7),n.addMany(x,7,0,7),n.add(156,7,0,0),n.add(127,7,0,7),n.add(91,1,11,3),n.addMany(p(64,127),3,7,0),n.addMany(p(48,60),3,8,4),n.addMany([60,61,62,63],3,9,4),n.addMany(p(48,60),4,8,4),n.addMany(p(64,127),4,7,0),n.addMany([60,61,62,63],4,0,6),n.addMany(p(32,64),6,0,6),n.add(127,6,0,6),n.addMany(p(64,127),6,0,0),n.addMany(p(32,48),3,9,5),n.addMany(p(32,48),5,9,5),n.addMany(p(48,64),5,0,6),n.addMany(p(64,127),5,7,0),n.addMany(p(32,48),4,9,5),n.addMany(p(32,48),1,9,2),n.addMany(p(32,48),2,9,2),n.addMany(p(48,127),2,10,0),n.addMany(p(48,80),1,10,0),n.addMany(p(81,88),1,10,0),n.addMany([89,90,92],1,10,0),n.addMany(p(96,127),1,10,0),n.add(80,1,11,9),n.addMany(x,9,0,9),n.add(127,9,0,9),n.addMany(p(28,32),9,0,9),n.addMany(p(32,48),9,9,12),n.addMany(p(48,60),9,8,10),n.addMany([60,61,62,63],9,9,10),n.addMany(x,11,0,11),n.addMany(p(32,128),11,0,11),n.addMany(p(28,32),11,0,11),n.addMany(x,10,0,10),n.add(127,10,0,10),n.addMany(p(28,32),10,0,10),n.addMany(p(48,60),10,8,10),n.addMany([60,61,62,63],10,0,11),n.addMany(p(32,48),10,9,12),n.addMany(x,12,0,12),n.add(127,12,0,12),n.addMany(p(28,32),12,0,12),n.addMany(p(32,48),12,9,12),n.addMany(p(48,64),12,0,11),n.addMany(p(64,127),12,12,13),n.addMany(p(64,127),10,12,13),n.addMany(p(64,127),9,12,13),n.addMany(x,13,13,13),n.addMany(u,13,13,13),n.add(127,13,0,13),n.addMany([27,156,24,26],13,14,0),n.add(b,0,2,0),n.add(b,8,5,8),n.add(b,6,0,6),n.add(b,11,0,11),n.add(b,13,13,13),n}();class w extends g.Disposable{constructor(d=r.VT500_TRANSITION_TABLE){super(),this._transitions=d,this._parseStack={state:0,handlers:[],handlerPos:0,transition:0,chunkPos:0},this.initialState=0,this.currentState=this.initialState,this._params=new m.Params,this._params.addParam(0),this._collect=0,this.precedingJoinState=0,this._printHandlerFb=(p,u,x)=>{},this._executeHandlerFb=p=>{},this._csiHandlerFb=(p,u)=>{},this._escHandlerFb=p=>{},this._errorHandlerFb=p=>p,this._printHandler=this._printHandlerFb,this._executeHandlers=Object.create(null),this._csiHandlers=Object.create(null),this._escHandlers=Object.create(null),this.register((0,g.toDisposable)(()=>{this._csiHandlers=Object.create(null),this._executeHandlers=Object.create(null),this._escHandlers=Object.create(null)})),this._oscParser=this.register(new l.OscParser),this._dcsParser=this.register(new v.DcsParser),this._errorHandler=this._errorHandlerFb,this.registerEscHandler({final:"\\"},()=>!0)}_identifier(d,p=[64,126]){let u=0;if(d.prefix){if(d.prefix.length>1)throw new Error("only one byte as prefix supported");if(u=d.prefix.charCodeAt(0),u&&60>u||u>63)throw new Error("prefix must be in range 0x3c .. 0x3f")}if(d.intermediates){if(d.intermediates.length>2)throw new Error("only two bytes as intermediates are supported");for(let k=0;k<d.intermediates.length;++k){let I=d.intermediates.charCodeAt(k);if(32>I||I>47)throw new Error("intermediate must be in range 0x20 .. 0x2f");u<<=8,u|=I}}if(d.final.length!==1)throw new Error("final must be a single byte");let x=d.final.charCodeAt(0);if(p[0]>x||x>p[1])throw new Error(`final must be in range ${p[0]} .. ${p[1]}`);return u<<=8,u|=x,u}identToString(d){let p=[];for(;d;)p.push(String.fromCharCode(255&d)),d>>=8;return p.reverse().join("")}setPrintHandler(d){this._printHandler=d}clearPrintHandler(){this._printHandler=this._printHandlerFb}registerEscHandler(d,p){let u=this._identifier(d,[48,126]);this._escHandlers[u]===void 0&&(this._escHandlers[u]=[]);let x=this._escHandlers[u];return x.push(p),{dispose:()=>{let k=x.indexOf(p);k!==-1&&x.splice(k,1)}}}clearEscHandler(d){this._escHandlers[this._identifier(d,[48,126])]&&delete this._escHandlers[this._identifier(d,[48,126])]}setEscHandlerFallback(d){this._escHandlerFb=d}setExecuteHandler(d,p){this._executeHandlers[d.charCodeAt(0)]=p}clearExecuteHandler(d){this._executeHandlers[d.charCodeAt(0)]&&delete this._executeHandlers[d.charCodeAt(0)]}setExecuteHandlerFallback(d){this._executeHandlerFb=d}registerCsiHandler(d,p){let u=this._identifier(d);this._csiHandlers[u]===void 0&&(this._csiHandlers[u]=[]);let x=this._csiHandlers[u];return x.push(p),{dispose:()=>{let k=x.indexOf(p);k!==-1&&x.splice(k,1)}}}clearCsiHandler(d){this._csiHandlers[this._identifier(d)]&&delete this._csiHandlers[this._identifier(d)]}setCsiHandlerFallback(d){this._csiHandlerFb=d}registerDcsHandler(d,p){return this._dcsParser.registerHandler(this._identifier(d),p)}clearDcsHandler(d){this._dcsParser.clearHandler(this._identifier(d))}setDcsHandlerFallback(d){this._dcsParser.setHandlerFallback(d)}registerOscHandler(d,p){return this._oscParser.registerHandler(d,p)}clearOscHandler(d){this._oscParser.clearHandler(d)}setOscHandlerFallback(d){this._oscParser.setHandlerFallback(d)}setErrorHandler(d){this._errorHandler=d}clearErrorHandler(){this._errorHandler=this._errorHandlerFb}reset(){this.currentState=this.initialState,this._oscParser.reset(),this._dcsParser.reset(),this._params.reset(),this._params.addParam(0),this._collect=0,this.precedingJoinState=0,this._parseStack.state!==0&&(this._parseStack.state=2,this._parseStack.handlers=[])}_preserveStack(d,p,u,x,k){this._parseStack.state=d,this._parseStack.handlers=p,this._parseStack.handlerPos=u,this._parseStack.transition=x,this._parseStack.chunkPos=k}parse(d,p,u){let x,k=0,I=0,P=0;if(this._parseStack.state)if(this._parseStack.state===2)this._parseStack.state=0,P=this._parseStack.chunkPos+1;else{if(u===void 0||this._parseStack.state===1)throw this._parseStack.state=1,new Error("improper continuation due to previous async handler, giving up parsing");let L=this._parseStack.handlers,D=this._parseStack.handlerPos-1;switch(this._parseStack.state){case 3:if(u===!1&&D>-1){for(;D>=0&&(x=L[D](this._params),x!==!0);D--)if(x instanceof Promise)return this._parseStack.handlerPos=D,x}this._parseStack.handlers=[];break;case 4:if(u===!1&&D>-1){for(;D>=0&&(x=L[D](),x!==!0);D--)if(x instanceof Promise)return this._parseStack.handlerPos=D,x}this._parseStack.handlers=[];break;case 6:if(k=d[this._parseStack.chunkPos],x=this._dcsParser.unhook(k!==24&&k!==26,u),x)return x;k===27&&(this._parseStack.transition|=1),this._params.reset(),this._params.addParam(0),this._collect=0;break;case 5:if(k=d[this._parseStack.chunkPos],x=this._oscParser.end(k!==24&&k!==26,u),x)return x;k===27&&(this._parseStack.transition|=1),this._params.reset(),this._params.addParam(0),this._collect=0}this._parseStack.state=0,P=this._parseStack.chunkPos+1,this.precedingJoinState=0,this.currentState=15&this._parseStack.transition}for(let L=P;L<p;++L){switch(k=d[L],I=this._transitions.table[this.currentState<<8|(k<160?k:b)],I>>4){case 2:for(let O=L+1;;++O){if(O>=p||(k=d[O])<32||k>126&&k<b){this._printHandler(d,L,O),L=O-1;break}if(++O>=p||(k=d[O])<32||k>126&&k<b){this._printHandler(d,L,O),L=O-1;break}if(++O>=p||(k=d[O])<32||k>126&&k<b){this._printHandler(d,L,O),L=O-1;break}if(++O>=p||(k=d[O])<32||k>126&&k<b){this._printHandler(d,L,O),L=O-1;break}}break;case 3:this._executeHandlers[k]?this._executeHandlers[k]():this._executeHandlerFb(k),this.precedingJoinState=0;break;case 0:break;case 1:if(this._errorHandler({position:L,code:k,currentState:this.currentState,collect:this._collect,params:this._params,abort:!1}).abort)return;break;case 7:let D=this._csiHandlers[this._collect<<8|k],ie=D?D.length-1:-1;for(;ie>=0&&(x=D[ie](this._params),x!==!0);ie--)if(x instanceof Promise)return this._preserveStack(3,D,ie,I,L),x;ie<0&&this._csiHandlerFb(this._collect<<8|k,this._params),this.precedingJoinState=0;break;case 8:do switch(k){case 59:this._params.addParam(0);break;case 58:this._params.addSubParam(-1);break;default:this._params.addDigit(k-48)}while(++L<p&&(k=d[L])>47&&k<60);L--;break;case 9:this._collect<<=8,this._collect|=k;break;case 10:let H=this._escHandlers[this._collect<<8|k],R=H?H.length-1:-1;for(;R>=0&&(x=H[R](),x!==!0);R--)if(x instanceof Promise)return this._preserveStack(4,H,R,I,L),x;R<0&&this._escHandlerFb(this._collect<<8|k),this.precedingJoinState=0;break;case 11:this._params.reset(),this._params.addParam(0),this._collect=0;break;case 12:this._dcsParser.hook(this._collect<<8|k,this._params);break;case 13:for(let O=L+1;;++O)if(O>=p||(k=d[O])===24||k===26||k===27||k>127&&k<b){this._dcsParser.put(d,L,O),L=O-1;break}break;case 14:if(x=this._dcsParser.unhook(k!==24&&k!==26),x)return this._preserveStack(6,[],0,I,L),x;k===27&&(I|=1),this._params.reset(),this._params.addParam(0),this._collect=0,this.precedingJoinState=0;break;case 4:this._oscParser.start();break;case 5:for(let O=L+1;;O++)if(O>=p||(k=d[O])<32||k>127&&k<b){this._oscParser.put(d,L,O),L=O-1;break}break;case 6:if(x=this._oscParser.end(k!==24&&k!==26),x)return this._preserveStack(5,[],0,I,L),x;k===27&&(I|=1),this._params.reset(),this._params.addParam(0),this._collect=0,this.precedingJoinState=0}this.currentState=15&I}}}r.EscapeSequenceParser=w},242:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.OscHandler=r.OscParser=void 0;let g=a(770),m=a(482),l=[];r.OscParser=class{constructor(){this._state=0,this._active=l,this._id=-1,this._handlers=Object.create(null),this._handlerFb=()=>{},this._stack={paused:!1,loopPosition:0,fallThrough:!1}}registerHandler(v,f){this._handlers[v]===void 0&&(this._handlers[v]=[]);let b=this._handlers[v];return b.push(f),{dispose:()=>{let w=b.indexOf(f);w!==-1&&b.splice(w,1)}}}clearHandler(v){this._handlers[v]&&delete this._handlers[v]}setHandlerFallback(v){this._handlerFb=v}dispose(){this._handlers=Object.create(null),this._handlerFb=()=>{},this._active=l}reset(){if(this._state===2)for(let v=this._stack.paused?this._stack.loopPosition-1:this._active.length-1;v>=0;--v)this._active[v].end(!1);this._stack.paused=!1,this._active=l,this._id=-1,this._state=0}_start(){if(this._active=this._handlers[this._id]||l,this._active.length)for(let v=this._active.length-1;v>=0;v--)this._active[v].start();else this._handlerFb(this._id,"START")}_put(v,f,b){if(this._active.length)for(let w=this._active.length-1;w>=0;w--)this._active[w].put(v,f,b);else this._handlerFb(this._id,"PUT",(0,m.utf32ToString)(v,f,b))}start(){this.reset(),this._state=1}put(v,f,b){if(this._state!==3){if(this._state===1)for(;f<b;){let w=v[f++];if(w===59){this._state=2,this._start();break}if(w<48||57<w)return void(this._state=3);this._id===-1&&(this._id=0),this._id=10*this._id+w-48}this._state===2&&b-f>0&&this._put(v,f,b)}}end(v,f=!0){if(this._state!==0){if(this._state!==3)if(this._state===1&&this._start(),this._active.length){let b=!1,w=this._active.length-1,n=!1;if(this._stack.paused&&(w=this._stack.loopPosition-1,b=f,n=this._stack.fallThrough,this._stack.paused=!1),!n&&b===!1){for(;w>=0&&(b=this._active[w].end(v),b!==!0);w--)if(b instanceof Promise)return this._stack.paused=!0,this._stack.loopPosition=w,this._stack.fallThrough=!1,b;w--}for(;w>=0;w--)if(b=this._active[w].end(!1),b instanceof Promise)return this._stack.paused=!0,this._stack.loopPosition=w,this._stack.fallThrough=!0,b}else this._handlerFb(this._id,"END",v);this._active=l,this._id=-1,this._state=0}}},r.OscHandler=class{constructor(v){this._handler=v,this._data="",this._hitLimit=!1}start(){this._data="",this._hitLimit=!1}put(v,f,b){this._hitLimit||(this._data+=(0,m.utf32ToString)(v,f,b),this._data.length>g.PAYLOAD_LIMIT&&(this._data="",this._hitLimit=!0))}end(v){let f=!1;if(this._hitLimit)f=!1;else if(v&&(f=this._handler(this._data),f instanceof Promise))return f.then(b=>(this._data="",this._hitLimit=!1,b));return this._data="",this._hitLimit=!1,f}}},742:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.Params=void 0;let a=2147483647;class g{static fromArray(l){let v=new g;if(!l.length)return v;for(let f=Array.isArray(l[0])?1:0;f<l.length;++f){let b=l[f];if(Array.isArray(b))for(let w=0;w<b.length;++w)v.addSubParam(b[w]);else v.addParam(b)}return v}constructor(l=32,v=32){if(this.maxLength=l,this.maxSubParamsLength=v,v>256)throw new Error("maxSubParamsLength must not be greater than 256");this.params=new Int32Array(l),this.length=0,this._subParams=new Int32Array(v),this._subParamsLength=0,this._subParamsIdx=new Uint16Array(l),this._rejectDigits=!1,this._rejectSubDigits=!1,this._digitIsSub=!1}clone(){let l=new g(this.maxLength,this.maxSubParamsLength);return l.params.set(this.params),l.length=this.length,l._subParams.set(this._subParams),l._subParamsLength=this._subParamsLength,l._subParamsIdx.set(this._subParamsIdx),l._rejectDigits=this._rejectDigits,l._rejectSubDigits=this._rejectSubDigits,l._digitIsSub=this._digitIsSub,l}toArray(){let l=[];for(let v=0;v<this.length;++v){l.push(this.params[v]);let f=this._subParamsIdx[v]>>8,b=255&this._subParamsIdx[v];b-f>0&&l.push(Array.prototype.slice.call(this._subParams,f,b))}return l}reset(){this.length=0,this._subParamsLength=0,this._rejectDigits=!1,this._rejectSubDigits=!1,this._digitIsSub=!1}addParam(l){if(this._digitIsSub=!1,this.length>=this.maxLength)this._rejectDigits=!0;else{if(l<-1)throw new Error("values lesser than -1 are not allowed");this._subParamsIdx[this.length]=this._subParamsLength<<8|this._subParamsLength,this.params[this.length++]=l>a?a:l}}addSubParam(l){if(this._digitIsSub=!0,this.length)if(this._rejectDigits||this._subParamsLength>=this.maxSubParamsLength)this._rejectSubDigits=!0;else{if(l<-1)throw new Error("values lesser than -1 are not allowed");this._subParams[this._subParamsLength++]=l>a?a:l,this._subParamsIdx[this.length-1]++}}hasSubParams(l){return(255&this._subParamsIdx[l])-(this._subParamsIdx[l]>>8)>0}getSubParams(l){let v=this._subParamsIdx[l]>>8,f=255&this._subParamsIdx[l];return f-v>0?this._subParams.subarray(v,f):null}getSubParamsAll(){let l={};for(let v=0;v<this.length;++v){let f=this._subParamsIdx[v]>>8,b=255&this._subParamsIdx[v];b-f>0&&(l[v]=this._subParams.slice(f,b))}return l}addDigit(l){let v;if(this._rejectDigits||!(v=this._digitIsSub?this._subParamsLength:this.length)||this._digitIsSub&&this._rejectSubDigits)return;let f=this._digitIsSub?this._subParams:this.params,b=f[v-1];f[v-1]=~b?Math.min(10*b+l,a):l}}r.Params=g},741:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.AddonManager=void 0,r.AddonManager=class{constructor(){this._addons=[]}dispose(){for(let a=this._addons.length-1;a>=0;a--)this._addons[a].instance.dispose()}loadAddon(a,g){let m={instance:g,dispose:g.dispose,isDisposed:!1};this._addons.push(m),g.dispose=()=>this._wrappedAddonDispose(m),g.activate(a)}_wrappedAddonDispose(a){if(a.isDisposed)return;let g=-1;for(let m=0;m<this._addons.length;m++)if(this._addons[m]===a){g=m;break}if(g===-1)throw new Error("Could not dispose an addon that has not been loaded");a.isDisposed=!0,a.dispose.apply(a.instance),this._addons.splice(g,1)}}},771:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.BufferApiView=void 0;let g=a(785),m=a(511);r.BufferApiView=class{constructor(l,v){this._buffer=l,this.type=v}init(l){return this._buffer=l,this}get cursorY(){return this._buffer.y}get cursorX(){return this._buffer.x}get viewportY(){return this._buffer.ydisp}get baseY(){return this._buffer.ybase}get length(){return this._buffer.lines.length}getLine(l){let v=this._buffer.lines.get(l);if(v)return new g.BufferLineApiView(v)}getNullCell(){return new m.CellData}}},785:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.BufferLineApiView=void 0;let g=a(511);r.BufferLineApiView=class{constructor(m){this._line=m}get isWrapped(){return this._line.isWrapped}get length(){return this._line.length}getCell(m,l){if(!(m<0||m>=this._line.length))return l?(this._line.loadCell(m,l),l):this._line.loadCell(m,new g.CellData)}translateToString(m,l,v){return this._line.translateToString(m,l,v)}}},285:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.BufferNamespaceApi=void 0;let g=a(771),m=a(460),l=a(844);class v extends l.Disposable{constructor(b){super(),this._core=b,this._onBufferChange=this.register(new m.EventEmitter),this.onBufferChange=this._onBufferChange.event,this._normal=new g.BufferApiView(this._core.buffers.normal,"normal"),this._alternate=new g.BufferApiView(this._core.buffers.alt,"alternate"),this._core.buffers.onBufferActivate(()=>this._onBufferChange.fire(this.active))}get active(){if(this._core.buffers.active===this._core.buffers.normal)return this.normal;if(this._core.buffers.active===this._core.buffers.alt)return this.alternate;throw new Error("Active buffer is neither normal nor alternate")}get normal(){return this._normal.init(this._core.buffers.normal)}get alternate(){return this._alternate.init(this._core.buffers.alt)}}r.BufferNamespaceApi=v},975:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.ParserApi=void 0,r.ParserApi=class{constructor(a){this._core=a}registerCsiHandler(a,g){return this._core.registerCsiHandler(a,m=>g(m.toArray()))}addCsiHandler(a,g){return this.registerCsiHandler(a,g)}registerDcsHandler(a,g){return this._core.registerDcsHandler(a,(m,l)=>g(m,l.toArray()))}addDcsHandler(a,g){return this.registerDcsHandler(a,g)}registerEscHandler(a,g){return this._core.registerEscHandler(a,g)}addEscHandler(a,g){return this.registerEscHandler(a,g)}registerOscHandler(a,g){return this._core.registerOscHandler(a,g)}addOscHandler(a,g){return this.registerOscHandler(a,g)}}},90:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.UnicodeApi=void 0,r.UnicodeApi=class{constructor(a){this._core=a}register(a){this._core.unicodeService.register(a)}get versions(){return this._core.unicodeService.versions}get activeVersion(){return this._core.unicodeService.activeVersion}set activeVersion(a){this._core.unicodeService.activeVersion=a}}},744:function(c,r,a){var g=this&&this.__decorate||function(n,d,p,u){var x,k=arguments.length,I=k<3?d:u===null?u=Object.getOwnPropertyDescriptor(d,p):u;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")I=Reflect.decorate(n,d,p,u);else for(var P=n.length-1;P>=0;P--)(x=n[P])&&(I=(k<3?x(I):k>3?x(d,p,I):x(d,p))||I);return k>3&&I&&Object.defineProperty(d,p,I),I},m=this&&this.__param||function(n,d){return function(p,u){d(p,u,n)}};Object.defineProperty(r,"__esModule",{value:!0}),r.BufferService=r.MINIMUM_ROWS=r.MINIMUM_COLS=void 0;let l=a(460),v=a(844),f=a(295),b=a(585);r.MINIMUM_COLS=2,r.MINIMUM_ROWS=1;let w=r.BufferService=class extends v.Disposable{get buffer(){return this.buffers.active}constructor(n){super(),this.isUserScrolling=!1,this._onResize=this.register(new l.EventEmitter),this.onResize=this._onResize.event,this._onScroll=this.register(new l.EventEmitter),this.onScroll=this._onScroll.event,this.cols=Math.max(n.rawOptions.cols||0,r.MINIMUM_COLS),this.rows=Math.max(n.rawOptions.rows||0,r.MINIMUM_ROWS),this.buffers=this.register(new f.BufferSet(n,this))}resize(n,d){this.cols=n,this.rows=d,this.buffers.resize(n,d),this._onResize.fire({cols:n,rows:d})}reset(){this.buffers.reset(),this.isUserScrolling=!1}scroll(n,d=!1){let p=this.buffer,u;u=this._cachedBlankLine,u&&u.length===this.cols&&u.getFg(0)===n.fg&&u.getBg(0)===n.bg||(u=p.getBlankLine(n,d),this._cachedBlankLine=u),u.isWrapped=d;let x=p.ybase+p.scrollTop,k=p.ybase+p.scrollBottom;if(p.scrollTop===0){let I=p.lines.isFull;k===p.lines.length-1?I?p.lines.recycle().copyFrom(u):p.lines.push(u.clone()):p.lines.splice(k+1,0,u.clone()),I?this.isUserScrolling&&(p.ydisp=Math.max(p.ydisp-1,0)):(p.ybase++,this.isUserScrolling||p.ydisp++)}else{let I=k-x+1;p.lines.shiftElements(x+1,I-1,-1),p.lines.set(k,u.clone())}this.isUserScrolling||(p.ydisp=p.ybase),this._onScroll.fire(p.ydisp)}scrollLines(n,d,p){let u=this.buffer;if(n<0){if(u.ydisp===0)return;this.isUserScrolling=!0}else n+u.ydisp>=u.ybase&&(this.isUserScrolling=!1);let x=u.ydisp;u.ydisp=Math.max(Math.min(u.ydisp+n,u.ybase),0),x!==u.ydisp&&(d||this._onScroll.fire(u.ydisp))}};r.BufferService=w=g([m(0,b.IOptionsService)],w)},994:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.CharsetService=void 0,r.CharsetService=class{constructor(){this.glevel=0,this._charsets=[]}reset(){this.charset=void 0,this._charsets=[],this.glevel=0}setgLevel(a){this.glevel=a,this.charset=this._charsets[a]}setgCharset(a,g){this._charsets[a]=g,this.glevel===a&&(this.charset=g)}}},753:function(c,r,a){var g=this&&this.__decorate||function(u,x,k,I){var P,L=arguments.length,D=L<3?x:I===null?I=Object.getOwnPropertyDescriptor(x,k):I;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")D=Reflect.decorate(u,x,k,I);else for(var ie=u.length-1;ie>=0;ie--)(P=u[ie])&&(D=(L<3?P(D):L>3?P(x,k,D):P(x,k))||D);return L>3&&D&&Object.defineProperty(x,k,D),D},m=this&&this.__param||function(u,x){return function(k,I){x(k,I,u)}};Object.defineProperty(r,"__esModule",{value:!0}),r.CoreMouseService=void 0;let l=a(585),v=a(460),f=a(844),b={NONE:{events:0,restrict:()=>!1},X10:{events:1,restrict:u=>u.button!==4&&u.action===1&&(u.ctrl=!1,u.alt=!1,u.shift=!1,!0)},VT200:{events:19,restrict:u=>u.action!==32},DRAG:{events:23,restrict:u=>u.action!==32||u.button!==3},ANY:{events:31,restrict:u=>!0}};function w(u,x){let k=(u.ctrl?16:0)|(u.shift?4:0)|(u.alt?8:0);return u.button===4?(k|=64,k|=u.action):(k|=3&u.button,4&u.button&&(k|=64),8&u.button&&(k|=128),u.action===32?k|=32:u.action!==0||x||(k|=3)),k}let n=String.fromCharCode,d={DEFAULT:u=>{let x=[w(u,!1)+32,u.col+32,u.row+32];return x[0]>255||x[1]>255||x[2]>255?"":`\x1B[M${n(x[0])}${n(x[1])}${n(x[2])}`},SGR:u=>{let x=u.action===0&&u.button!==4?"m":"M";return`\x1B[<${w(u,!0)};${u.col};${u.row}${x}`},SGR_PIXELS:u=>{let x=u.action===0&&u.button!==4?"m":"M";return`\x1B[<${w(u,!0)};${u.x};${u.y}${x}`}},p=r.CoreMouseService=class extends f.Disposable{constructor(u,x){super(),this._bufferService=u,this._coreService=x,this._protocols={},this._encodings={},this._activeProtocol="",this._activeEncoding="",this._lastEvent=null,this._onProtocolChange=this.register(new v.EventEmitter),this.onProtocolChange=this._onProtocolChange.event;for(let k of Object.keys(b))this.addProtocol(k,b[k]);for(let k of Object.keys(d))this.addEncoding(k,d[k]);this.reset()}addProtocol(u,x){this._protocols[u]=x}addEncoding(u,x){this._encodings[u]=x}get activeProtocol(){return this._activeProtocol}get areMouseEventsActive(){return this._protocols[this._activeProtocol].events!==0}set activeProtocol(u){if(!this._protocols[u])throw new Error(`unknown protocol "${u}"`);this._activeProtocol=u,this._onProtocolChange.fire(this._protocols[u].events)}get activeEncoding(){return this._activeEncoding}set activeEncoding(u){if(!this._encodings[u])throw new Error(`unknown encoding "${u}"`);this._activeEncoding=u}reset(){this.activeProtocol="NONE",this.activeEncoding="DEFAULT",this._lastEvent=null}triggerMouseEvent(u){if(u.col<0||u.col>=this._bufferService.cols||u.row<0||u.row>=this._bufferService.rows||u.button===4&&u.action===32||u.button===3&&u.action!==32||u.button!==4&&(u.action===2||u.action===3)||(u.col++,u.row++,u.action===32&&this._lastEvent&&this._equalEvents(this._lastEvent,u,this._activeEncoding==="SGR_PIXELS"))||!this._protocols[this._activeProtocol].restrict(u))return!1;let x=this._encodings[this._activeEncoding](u);return x&&(this._activeEncoding==="DEFAULT"?this._coreService.triggerBinaryEvent(x):this._coreService.triggerDataEvent(x,!0)),this._lastEvent=u,!0}explainEvents(u){return{down:!!(1&u),up:!!(2&u),drag:!!(4&u),move:!!(8&u),wheel:!!(16&u)}}_equalEvents(u,x,k){if(k){if(u.x!==x.x||u.y!==x.y)return!1}else if(u.col!==x.col||u.row!==x.row)return!1;return u.button===x.button&&u.action===x.action&&u.ctrl===x.ctrl&&u.alt===x.alt&&u.shift===x.shift}};r.CoreMouseService=p=g([m(0,l.IBufferService),m(1,l.ICoreService)],p)},83:function(c,r,a){var g=this&&this.__decorate||function(p,u,x,k){var I,P=arguments.length,L=P<3?u:k===null?k=Object.getOwnPropertyDescriptor(u,x):k;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")L=Reflect.decorate(p,u,x,k);else for(var D=p.length-1;D>=0;D--)(I=p[D])&&(L=(P<3?I(L):P>3?I(u,x,L):I(u,x))||L);return P>3&&L&&Object.defineProperty(u,x,L),L},m=this&&this.__param||function(p,u){return function(x,k){u(x,k,p)}};Object.defineProperty(r,"__esModule",{value:!0}),r.CoreService=void 0;let l=a(439),v=a(460),f=a(844),b=a(585),w=Object.freeze({insertMode:!1}),n=Object.freeze({applicationCursorKeys:!1,applicationKeypad:!1,bracketedPasteMode:!1,origin:!1,reverseWraparound:!1,sendFocus:!1,wraparound:!0}),d=r.CoreService=class extends f.Disposable{constructor(p,u,x){super(),this._bufferService=p,this._logService=u,this._optionsService=x,this.isCursorInitialized=!1,this.isCursorHidden=!1,this._onData=this.register(new v.EventEmitter),this.onData=this._onData.event,this._onUserInput=this.register(new v.EventEmitter),this.onUserInput=this._onUserInput.event,this._onBinary=this.register(new v.EventEmitter),this.onBinary=this._onBinary.event,this._onRequestScrollToBottom=this.register(new v.EventEmitter),this.onRequestScrollToBottom=this._onRequestScrollToBottom.event,this.modes=(0,l.clone)(w),this.decPrivateModes=(0,l.clone)(n)}reset(){this.modes=(0,l.clone)(w),this.decPrivateModes=(0,l.clone)(n)}triggerDataEvent(p,u=!1){if(this._optionsService.rawOptions.disableStdin)return;let x=this._bufferService.buffer;u&&this._optionsService.rawOptions.scrollOnUserInput&&x.ybase!==x.ydisp&&this._onRequestScrollToBottom.fire(),u&&this._onUserInput.fire(),this._logService.debug(`sending data "${p}"`,()=>p.split("").map(k=>k.charCodeAt(0))),this._onData.fire(p)}triggerBinaryEvent(p){this._optionsService.rawOptions.disableStdin||(this._logService.debug(`sending binary "${p}"`,()=>p.split("").map(u=>u.charCodeAt(0))),this._onBinary.fire(p))}};r.CoreService=d=g([m(0,b.IBufferService),m(1,b.ILogService),m(2,b.IOptionsService)],d)},348:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.InstantiationService=r.ServiceCollection=void 0;let g=a(585),m=a(343);class l{constructor(...f){this._entries=new Map;for(let[b,w]of f)this.set(b,w)}set(f,b){let w=this._entries.get(f);return this._entries.set(f,b),w}forEach(f){for(let[b,w]of this._entries.entries())f(b,w)}has(f){return this._entries.has(f)}get(f){return this._entries.get(f)}}r.ServiceCollection=l,r.InstantiationService=class{constructor(){this._services=new l,this._services.set(g.IInstantiationService,this)}setService(v,f){this._services.set(v,f)}getService(v){return this._services.get(v)}createInstance(v,...f){let b=(0,m.getServiceDependencies)(v).sort((d,p)=>d.index-p.index),w=[];for(let d of b){let p=this._services.get(d.id);if(!p)throw new Error(`[createInstance] ${v.name} depends on UNKNOWN service ${d.id}.`);w.push(p)}let n=b.length>0?b[0].index:f.length;if(f.length!==n)throw new Error(`[createInstance] First service dependency of ${v.name} at position ${n+1} conflicts with ${f.length} static arguments`);return new v(...f,...w)}}},866:function(c,r,a){var g=this&&this.__decorate||function(n,d,p,u){var x,k=arguments.length,I=k<3?d:u===null?u=Object.getOwnPropertyDescriptor(d,p):u;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")I=Reflect.decorate(n,d,p,u);else for(var P=n.length-1;P>=0;P--)(x=n[P])&&(I=(k<3?x(I):k>3?x(d,p,I):x(d,p))||I);return k>3&&I&&Object.defineProperty(d,p,I),I},m=this&&this.__param||function(n,d){return function(p,u){d(p,u,n)}};Object.defineProperty(r,"__esModule",{value:!0}),r.traceCall=r.setTraceLogger=r.LogService=void 0;let l=a(844),v=a(585),f={trace:v.LogLevelEnum.TRACE,debug:v.LogLevelEnum.DEBUG,info:v.LogLevelEnum.INFO,warn:v.LogLevelEnum.WARN,error:v.LogLevelEnum.ERROR,off:v.LogLevelEnum.OFF},b,w=r.LogService=class extends l.Disposable{get logLevel(){return this._logLevel}constructor(n){super(),this._optionsService=n,this._logLevel=v.LogLevelEnum.OFF,this._updateLogLevel(),this.register(this._optionsService.onSpecificOptionChange("logLevel",()=>this._updateLogLevel())),b=this}_updateLogLevel(){this._logLevel=f[this._optionsService.rawOptions.logLevel]}_evalLazyOptionalParams(n){for(let d=0;d<n.length;d++)typeof n[d]=="function"&&(n[d]=n[d]())}_log(n,d,p){this._evalLazyOptionalParams(p),n.call(console,(this._optionsService.options.logger?"":"xterm.js: ")+d,...p)}trace(n,...d){this._logLevel<=v.LogLevelEnum.TRACE&&this._log(this._optionsService.options.logger?.trace.bind(this._optionsService.options.logger)??console.log,n,d)}debug(n,...d){this._logLevel<=v.LogLevelEnum.DEBUG&&this._log(this._optionsService.options.logger?.debug.bind(this._optionsService.options.logger)??console.log,n,d)}info(n,...d){this._logLevel<=v.LogLevelEnum.INFO&&this._log(this._optionsService.options.logger?.info.bind(this._optionsService.options.logger)??console.info,n,d)}warn(n,...d){this._logLevel<=v.LogLevelEnum.WARN&&this._log(this._optionsService.options.logger?.warn.bind(this._optionsService.options.logger)??console.warn,n,d)}error(n,...d){this._logLevel<=v.LogLevelEnum.ERROR&&this._log(this._optionsService.options.logger?.error.bind(this._optionsService.options.logger)??console.error,n,d)}};r.LogService=w=g([m(0,v.IOptionsService)],w),r.setTraceLogger=function(n){b=n},r.traceCall=function(n,d,p){if(typeof p.value!="function")throw new Error("not supported");let u=p.value;p.value=function(...x){if(b.logLevel!==v.LogLevelEnum.TRACE)return u.apply(this,x);b.trace(`GlyphRenderer#${u.name}(${x.map(I=>JSON.stringify(I)).join(", ")})`);let k=u.apply(this,x);return b.trace(`GlyphRenderer#${u.name} return`,k),k}}},302:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.OptionsService=r.DEFAULT_OPTIONS=void 0;let g=a(460),m=a(844),l=a(114);r.DEFAULT_OPTIONS={cols:80,rows:24,cursorBlink:!1,cursorStyle:"block",cursorWidth:1,cursorInactiveStyle:"outline",customGlyphs:!0,drawBoldTextInBrightColors:!0,documentOverride:null,fastScrollModifier:"alt",fastScrollSensitivity:5,fontFamily:"courier-new, courier, monospace",fontSize:15,fontWeight:"normal",fontWeightBold:"bold",ignoreBracketedPasteMode:!1,lineHeight:1,letterSpacing:0,linkHandler:null,logLevel:"info",logger:null,scrollback:1e3,scrollOnUserInput:!0,scrollSensitivity:1,screenReaderMode:!1,smoothScrollDuration:0,macOptionIsMeta:!1,macOptionClickForcesSelection:!1,minimumContrastRatio:1,disableStdin:!1,allowProposedApi:!1,allowTransparency:!1,tabStopWidth:8,theme:{},rescaleOverlappingGlyphs:!1,rightClickSelectsWord:l.isMac,windowOptions:{},windowsMode:!1,windowsPty:{},wordSeparator:" ()[]{}',\"`",altClickMovesCursor:!0,convertEol:!1,termName:"xterm",cancelEvents:!1,overviewRulerWidth:0};let v=["normal","bold","100","200","300","400","500","600","700","800","900"];class f extends m.Disposable{constructor(w){super(),this._onOptionChange=this.register(new g.EventEmitter),this.onOptionChange=this._onOptionChange.event;let n={...r.DEFAULT_OPTIONS};for(let d in w)if(d in n)try{let p=w[d];n[d]=this._sanitizeAndValidateOption(d,p)}catch(p){console.error(p)}this.rawOptions=n,this.options={...n},this._setupOptions(),this.register((0,m.toDisposable)(()=>{this.rawOptions.linkHandler=null,this.rawOptions.documentOverride=null}))}onSpecificOptionChange(w,n){return this.onOptionChange(d=>{d===w&&n(this.rawOptions[w])})}onMultipleOptionChange(w,n){return this.onOptionChange(d=>{w.indexOf(d)!==-1&&n()})}_setupOptions(){let w=d=>{if(!(d in r.DEFAULT_OPTIONS))throw new Error(`No option with key "${d}"`);return this.rawOptions[d]},n=(d,p)=>{if(!(d in r.DEFAULT_OPTIONS))throw new Error(`No option with key "${d}"`);p=this._sanitizeAndValidateOption(d,p),this.rawOptions[d]!==p&&(this.rawOptions[d]=p,this._onOptionChange.fire(d))};for(let d in this.rawOptions){let p={get:w.bind(this,d),set:n.bind(this,d)};Object.defineProperty(this.options,d,p)}}_sanitizeAndValidateOption(w,n){switch(w){case"cursorStyle":if(n||(n=r.DEFAULT_OPTIONS[w]),!function(d){return d==="block"||d==="underline"||d==="bar"}(n))throw new Error(`"${n}" is not a valid value for ${w}`);break;case"wordSeparator":n||(n=r.DEFAULT_OPTIONS[w]);break;case"fontWeight":case"fontWeightBold":if(typeof n=="number"&&1<=n&&n<=1e3)break;n=v.includes(n)?n:r.DEFAULT_OPTIONS[w];break;case"cursorWidth":n=Math.floor(n);case"lineHeight":case"tabStopWidth":if(n<1)throw new Error(`${w} cannot be less than 1, value: ${n}`);break;case"minimumContrastRatio":n=Math.max(1,Math.min(21,Math.round(10*n)/10));break;case"scrollback":if((n=Math.min(n,4294967295))<0)throw new Error(`${w} cannot be less than 0, value: ${n}`);break;case"fastScrollSensitivity":case"scrollSensitivity":if(n<=0)throw new Error(`${w} cannot be less than or equal to 0, value: ${n}`);break;case"rows":case"cols":if(!n&&n!==0)throw new Error(`${w} must be numeric, value: ${n}`);break;case"windowsPty":n=n??{}}return n}}r.OptionsService=f},660:function(c,r,a){var g=this&&this.__decorate||function(f,b,w,n){var d,p=arguments.length,u=p<3?b:n===null?n=Object.getOwnPropertyDescriptor(b,w):n;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")u=Reflect.decorate(f,b,w,n);else for(var x=f.length-1;x>=0;x--)(d=f[x])&&(u=(p<3?d(u):p>3?d(b,w,u):d(b,w))||u);return p>3&&u&&Object.defineProperty(b,w,u),u},m=this&&this.__param||function(f,b){return function(w,n){b(w,n,f)}};Object.defineProperty(r,"__esModule",{value:!0}),r.OscLinkService=void 0;let l=a(585),v=r.OscLinkService=class{constructor(f){this._bufferService=f,this._nextId=1,this._entriesWithId=new Map,this._dataByLinkId=new Map}registerLink(f){let b=this._bufferService.buffer;if(f.id===void 0){let x=b.addMarker(b.ybase+b.y),k={data:f,id:this._nextId++,lines:[x]};return x.onDispose(()=>this._removeMarkerFromLink(k,x)),this._dataByLinkId.set(k.id,k),k.id}let w=f,n=this._getEntryIdKey(w),d=this._entriesWithId.get(n);if(d)return this.addLineToLink(d.id,b.ybase+b.y),d.id;let p=b.addMarker(b.ybase+b.y),u={id:this._nextId++,key:this._getEntryIdKey(w),data:w,lines:[p]};return p.onDispose(()=>this._removeMarkerFromLink(u,p)),this._entriesWithId.set(u.key,u),this._dataByLinkId.set(u.id,u),u.id}addLineToLink(f,b){let w=this._dataByLinkId.get(f);if(w&&w.lines.every(n=>n.line!==b)){let n=this._bufferService.buffer.addMarker(b);w.lines.push(n),n.onDispose(()=>this._removeMarkerFromLink(w,n))}}getLinkData(f){return this._dataByLinkId.get(f)?.data}_getEntryIdKey(f){return`${f.id};;${f.uri}`}_removeMarkerFromLink(f,b){let w=f.lines.indexOf(b);w!==-1&&(f.lines.splice(w,1),f.lines.length===0&&(f.data.id!==void 0&&this._entriesWithId.delete(f.key),this._dataByLinkId.delete(f.id)))}};r.OscLinkService=v=g([m(0,l.IBufferService)],v)},343:(c,r)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.createDecorator=r.getServiceDependencies=r.serviceRegistry=void 0;let a="di$target",g="di$dependencies";r.serviceRegistry=new Map,r.getServiceDependencies=function(m){return m[g]||[]},r.createDecorator=function(m){if(r.serviceRegistry.has(m))return r.serviceRegistry.get(m);let l=function(v,f,b){if(arguments.length!==3)throw new Error("@IServiceName-decorator can only be used to decorate a parameter");(function(w,n,d){n[a]===n?n[g].push({id:w,index:d}):(n[g]=[{id:w,index:d}],n[a]=n)})(l,v,b)};return l.toString=()=>m,r.serviceRegistry.set(m,l),l}},585:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.IDecorationService=r.IUnicodeService=r.IOscLinkService=r.IOptionsService=r.ILogService=r.LogLevelEnum=r.IInstantiationService=r.ICharsetService=r.ICoreService=r.ICoreMouseService=r.IBufferService=void 0;let g=a(343);var m;r.IBufferService=(0,g.createDecorator)("BufferService"),r.ICoreMouseService=(0,g.createDecorator)("CoreMouseService"),r.ICoreService=(0,g.createDecorator)("CoreService"),r.ICharsetService=(0,g.createDecorator)("CharsetService"),r.IInstantiationService=(0,g.createDecorator)("InstantiationService"),function(l){l[l.TRACE=0]="TRACE",l[l.DEBUG=1]="DEBUG",l[l.INFO=2]="INFO",l[l.WARN=3]="WARN",l[l.ERROR=4]="ERROR",l[l.OFF=5]="OFF"}(m||(r.LogLevelEnum=m={})),r.ILogService=(0,g.createDecorator)("LogService"),r.IOptionsService=(0,g.createDecorator)("OptionsService"),r.IOscLinkService=(0,g.createDecorator)("OscLinkService"),r.IUnicodeService=(0,g.createDecorator)("UnicodeService"),r.IDecorationService=(0,g.createDecorator)("DecorationService")},480:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.UnicodeService=void 0;let g=a(460),m=a(225);class l{static extractShouldJoin(f){return(1&f)!=0}static extractWidth(f){return f>>1&3}static extractCharKind(f){return f>>3}static createPropertyValue(f,b,w=!1){return(16777215&f)<<3|(3&b)<<1|(w?1:0)}constructor(){this._providers=Object.create(null),this._active="",this._onChange=new g.EventEmitter,this.onChange=this._onChange.event;let f=new m.UnicodeV6;this.register(f),this._active=f.version,this._activeProvider=f}dispose(){this._onChange.dispose()}get versions(){return Object.keys(this._providers)}get activeVersion(){return this._active}set activeVersion(f){if(!this._providers[f])throw new Error(`unknown Unicode version "${f}"`);this._active=f,this._activeProvider=this._providers[f],this._onChange.fire(f)}register(f){this._providers[f.version]=f}wcwidth(f){return this._activeProvider.wcwidth(f)}getStringCellWidth(f){let b=0,w=0,n=f.length;for(let d=0;d<n;++d){let p=f.charCodeAt(d);if(55296<=p&&p<=56319){if(++d>=n)return b+this.wcwidth(p);let k=f.charCodeAt(d);56320<=k&&k<=57343?p=1024*(p-55296)+k-56320+65536:b+=this.wcwidth(k)}let u=this.charProperties(p,w),x=l.extractWidth(u);l.extractShouldJoin(u)&&(x-=l.extractWidth(w)),b+=x,w=u}return b}charProperties(f,b){return this._activeProvider.charProperties(f,b)}}r.UnicodeService=l},781:(c,r,a)=>{Object.defineProperty(r,"__esModule",{value:!0}),r.Terminal=void 0;let g=a(437),m=a(969),l=a(460);class v extends m.CoreTerminal{constructor(b={}){super(b),this._onBell=this.register(new l.EventEmitter),this.onBell=this._onBell.event,this._onCursorMove=this.register(new l.EventEmitter),this.onCursorMove=this._onCursorMove.event,this._onTitleChange=this.register(new l.EventEmitter),this.onTitleChange=this._onTitleChange.event,this._onA11yCharEmitter=this.register(new l.EventEmitter),this.onA11yChar=this._onA11yCharEmitter.event,this._onA11yTabEmitter=this.register(new l.EventEmitter),this.onA11yTab=this._onA11yTabEmitter.event,this._setup(),this.register(this._inputHandler.onRequestBell(()=>this.bell())),this.register(this._inputHandler.onRequestReset(()=>this.reset())),this.register((0,l.forwardEvent)(this._inputHandler.onCursorMove,this._onCursorMove)),this.register((0,l.forwardEvent)(this._inputHandler.onTitleChange,this._onTitleChange)),this.register((0,l.forwardEvent)(this._inputHandler.onA11yChar,this._onA11yCharEmitter)),this.register((0,l.forwardEvent)(this._inputHandler.onA11yTab,this._onA11yTabEmitter))}get buffer(){return this.buffers.active}get markers(){return this.buffer.markers}addMarker(b){if(this.buffer===this.buffers.normal)return this.buffer.addMarker(this.buffer.ybase+this.buffer.y+b)}bell(){this._onBell.fire()}input(b,w=!0){this.coreService.triggerDataEvent(b,w)}resize(b,w){b===this.cols&&w===this.rows||super.resize(b,w)}clear(){if(this.buffer.ybase!==0||this.buffer.y!==0){this.buffer.lines.set(0,this.buffer.lines.get(this.buffer.ybase+this.buffer.y)),this.buffer.lines.length=1,this.buffer.ydisp=0,this.buffer.ybase=0,this.buffer.y=0;for(let b=1;b<this.rows;b++)this.buffer.lines.push(this.buffer.getBlankLine(g.DEFAULT_ATTR_DATA));this._onScroll.fire({position:this.buffer.ydisp,source:0})}}reset(){this.options.rows=this.rows,this.options.cols=this.cols,this._setup(),super.reset()}}r.Terminal=v}},t={};function e(c){var r=t[c];if(r!==void 0)return r.exports;var a=t[c]={exports:{}};return h[c].call(a.exports,a,a.exports,e),a.exports}var i={};(()=>{var c=i;Object.defineProperty(c,"__esModule",{value:!0}),c.Terminal=void 0;let r=e(285),a=e(975),g=e(90),m=e(781),l=e(741),v=e(844),f=["cols","rows"];class b extends v.Disposable{constructor(n){super(),this._core=this.register(new m.Terminal(n)),this._addonManager=this.register(new l.AddonManager),this._publicOptions={...this._core.options};let d=u=>this._core.options[u],p=(u,x)=>{this._checkReadonlyOptions(u),this._core.options[u]=x};for(let u in this._core.options){Object.defineProperty(this._publicOptions,u,{get:()=>this._core.options[u],set:k=>{this._checkReadonlyOptions(u),this._core.options[u]=k}});let x={get:d.bind(this,u),set:p.bind(this,u)};Object.defineProperty(this._publicOptions,u,x)}}_checkReadonlyOptions(n){if(f.includes(n))throw new Error(`Option "${n}" can only be set in the constructor`)}_checkProposedApi(){if(!this._core.optionsService.options.allowProposedApi)throw new Error("You must set the allowProposedApi option to true to use proposed API")}get onBell(){return this._core.onBell}get onBinary(){return this._core.onBinary}get onCursorMove(){return this._core.onCursorMove}get onData(){return this._core.onData}get onLineFeed(){return this._core.onLineFeed}get onResize(){return this._core.onResize}get onScroll(){return this._core.onScroll}get onTitleChange(){return this._core.onTitleChange}get parser(){return this._checkProposedApi(),this._parser||(this._parser=new a.ParserApi(this._core)),this._parser}get unicode(){return this._checkProposedApi(),new g.UnicodeApi(this._core)}get rows(){return this._core.rows}get cols(){return this._core.cols}get buffer(){return this._checkProposedApi(),this._buffer||(this._buffer=this.register(new r.BufferNamespaceApi(this._core))),this._buffer}get markers(){return this._checkProposedApi(),this._core.markers}get modes(){let n=this._core.coreService.decPrivateModes,d="none";switch(this._core.coreMouseService.activeProtocol){case"X10":d="x10";break;case"VT200":d="vt200";break;case"DRAG":d="drag";break;case"ANY":d="any"}return{applicationCursorKeysMode:n.applicationCursorKeys,applicationKeypadMode:n.applicationKeypad,bracketedPasteMode:n.bracketedPasteMode,insertMode:this._core.coreService.modes.insertMode,mouseTrackingMode:d,originMode:n.origin,reverseWraparoundMode:n.reverseWraparound,sendFocusMode:n.sendFocus,wraparoundMode:n.wraparound}}get options(){return this._publicOptions}set options(n){for(let d in n)this._publicOptions[d]=n[d]}input(n,d=!0){this._core.input(n,d)}resize(n,d){this._verifyIntegers(n,d),this._core.resize(n,d)}registerMarker(n=0){return this._checkProposedApi(),this._verifyIntegers(n),this._core.addMarker(n)}addMarker(n){return this.registerMarker(n)}dispose(){super.dispose()}scrollLines(n){this._verifyIntegers(n),this._core.scrollLines(n)}scrollPages(n){this._verifyIntegers(n),this._core.scrollPages(n)}scrollToTop(){this._core.scrollToTop()}scrollToBottom(){this._core.scrollToBottom()}scrollToLine(n){this._verifyIntegers(n),this._core.scrollToLine(n)}clear(){this._core.clear()}write(n,d){this._core.write(n,d)}writeln(n,d){this._core.write(n),this._core.write(`\r
`,d)}reset(){this._core.reset()}loadAddon(n){this._addonManager.loadAddon(this,n)}_verifyIntegers(...n){for(let d of n)if(d===1/0||isNaN(d)||d%1!=0)throw new Error("This API only accepts integers")}}c.Terminal=b})();var s=Us;for(var o in i)s[o]=i[o];i.__esModule&&Object.defineProperty(s,"__esModule",{value:!0})})()});Z();var kt=N("monaco-loader"),os=!1,qt=null;async function mr(){return qt||(qt=new Promise((h,t)=>{let e=document.createElement("script");e.src="/monaco-editor/vs/loader.js",e.onload=()=>{window.require.config({paths:{vs:"/monaco-editor/vs"}}),window.MonacoEnvironment={getWorker:(i,s)=>new Worker("data:,")},window.require(["vs/editor/editor.main"],()=>{kt.debug("Monaco Editor loaded via AMD"),h()})},e.onerror=()=>{t(new Error("Failed to load Monaco loader script"))},document.head.appendChild(e)}),qt)}async function Vt(){if(!os)try{kt.debug("Loading Monaco Editor..."),window.monaco||await mr(),kt.debug("Initializing Monaco Editor...");let h=window.monaco;h.languages.register({id:"shell"}),h.languages.setMonarchTokensProvider("shell",{tokenizer:{root:[[/^#.*$/,"comment"],[/\$\w+/,"variable"],[/\b(echo|cd|ls|grep|find|chmod|mkdir|rm|cp|mv|touch|cat|sed|awk|curl|wget|git|pnpm|npm|yarn|docker|kubectl)\b/,"keyword"],[/"([^"\\]|\\.)*"/,"string"],[/'([^'\\]|\\.)*'/,"string"]]}}),h.editor.setTheme("vs-dark"),os=!0,kt.debug("Monaco Editor initialized successfully")}catch(h){throw kt.error("Failed to initialize Monaco Editor:",h),h}}var fn=window.monaco;var Ei=(s=>(s.NONE="none",s.FILTER="filter",s.STATIC="static",s.DYNAMIC="dynamic",s))(Ei||{});Z();Pe();var Y=N("push-notification-service"),vr=null,Ti=class{constructor(){this.serviceWorkerRegistration=null;this.pushSubscription=null;this.permissionChangeCallbacks=new Set;this.subscriptionChangeCallbacks=new Set;this.initialized=!1;this.vapidPublicKey=null;this.pushNotificationsAvailable=!1;this.initializationPromise=null}async initialize(){return this.initializationPromise?this.initializationPromise:(this.initializationPromise=this._initialize().catch(t=>{Y.error("failed to initialize push notification service:",t)}),this.initializationPromise)}async _initialize(){if(!this.initialized)try{if(!("serviceWorker"in navigator)){Y.warn("service workers not supported");return}if(!("PushManager"in window)){Y.warn("push messaging not supported");return}await this.fetchVapidPublicKey(),this.serviceWorkerRegistration=await navigator.serviceWorker.register("/sw.js",{scope:"/"}),Y.log("service worker registered"),await navigator.serviceWorker.ready,this.pushSubscription=await this.serviceWorkerRegistration.pushManager.getSubscription(),navigator.serviceWorker.addEventListener("message",this.handleServiceWorkerMessage.bind(this)),this.monitorPermissionChanges(),this.initialized=!0,Y.log("push notification service initialized")}catch(t){throw Y.error("failed to initialize service worker:",t),t}}handleServiceWorkerMessage(t){let{data:e}=t;switch(e.type){case"notification-action":{this.handleNotificationAction(e.action,e.data);break}}}handleNotificationAction(t,e){window.dispatchEvent(new CustomEvent("notification-action",{detail:{action:t,data:e}}))}monitorPermissionChanges(){"permissions"in navigator&&navigator.permissions.query({name:"notifications"}).then(t=>{t.addEventListener("change",()=>{this.notifyPermissionChange(t.state)})}).catch(t=>{Y.warn("failed to monitor permission changes:",t)})}notifyPermissionChange(t){this.permissionChangeCallbacks.forEach(e=>{try{e(t)}catch(i){Y.error("error in permission change callback:",i)}})}notifySubscriptionChange(t){this.subscriptionChangeCallbacks.forEach(e=>{try{e(t)}catch(i){Y.error("error in subscription change callback:",i)}})}async requestPermission(){if(!("Notification"in window))throw new Error("Notifications not supported");let t=Notification.permission;return t==="default"&&(t=await Notification.requestPermission()),this.notifyPermissionChange(t),t}getPermission(){return"Notification"in window?Notification.permission:"denied"}async subscribe(){if(!this.serviceWorkerRegistration)throw new Error("Service worker not initialized");try{if(await this.requestPermission()!=="granted")throw new Error("Notification permission denied");if(!this.vapidPublicKey)throw new Error("VAPID public key not available");let e=this.urlBase64ToUint8Array(this.vapidPublicKey);this.pushSubscription=await this.serviceWorkerRegistration.pushManager.subscribe({userVisibleOnly:!0,applicationServerKey:e});let i=this.pushSubscriptionToInterface(this.pushSubscription);return await this.sendSubscriptionToServer(i),this.notifySubscriptionChange(i),Y.log("successfully subscribed to push notifications"),i}catch(t){throw Y.error("failed to subscribe to push notifications:",t),t}}async unsubscribe(){if(this.pushSubscription)try{await this.pushSubscription.unsubscribe(),await this.removeSubscriptionFromServer(),this.pushSubscription=null,this.notifySubscriptionChange(null),Y.log("successfully unsubscribed from push notifications")}catch(t){throw Y.error("failed to unsubscribe from push notifications:",t),t}}getSubscription(){return this.pushSubscription?this.pushSubscriptionToInterface(this.pushSubscription):null}async waitForInitialization(){this.initializationPromise&&await this.initializationPromise}isSupported(){return"serviceWorker"in navigator&&"PushManager"in window&&"Notification"in window?this.isIOSSafari()?this.isStandalone():!0:!1}isIOSSafari(){let t=navigator.userAgent.toLowerCase();return/iphone|ipad|ipod/.test(t)}isStandalone(){return window.matchMedia("(display-mode: standalone)").matches||"standalone"in window.navigator&&window.navigator.standalone===!0}isSubscribed(){return this.pushSubscription!==null}async testNotification(){if(!this.serviceWorkerRegistration)throw new Error("Service worker not initialized");if(this.getPermission()!=="granted")throw new Error("Notification permission not granted");try{await this.serviceWorkerRegistration.showNotification("VibeTunnel Test",{body:"Push notifications are working correctly!",icon:"/apple-touch-icon.png",badge:"/favicon-32.png",tag:"vibetunnel-test",requireInteraction:!1}),Y.log("test notification sent")}catch(e){throw Y.error("failed to send test notification:",e),e}}async clearAllNotifications(){if(this.serviceWorkerRegistration)try{let t=await this.serviceWorkerRegistration.getNotifications();for(let e of t)e.tag?.startsWith("vibetunnel-")&&e.close();Y.log("cleared all notifications")}catch(t){Y.error("failed to clear notifications:",t)}}savePreferences(t){try{localStorage.setItem("vibetunnel-notification-preferences",JSON.stringify(t)),Y.debug("saved notification preferences")}catch(e){Y.error("failed to save notification preferences:",e)}}loadPreferences(){try{let t=localStorage.getItem("vibetunnel-notification-preferences");if(t)return{...this.getDefaultPreferences(),...JSON.parse(t)}}catch(t){Y.error("failed to load notification preferences:",t)}return this.getDefaultPreferences()}getDefaultPreferences(){return{enabled:!1,sessionExit:!0,sessionStart:!1,sessionError:!0,systemAlerts:!0,soundEnabled:!0,vibrationEnabled:!0}}onPermissionChange(t){return this.permissionChangeCallbacks.add(t),()=>this.permissionChangeCallbacks.delete(t)}onSubscriptionChange(t){return this.subscriptionChangeCallbacks.add(t),()=>this.subscriptionChangeCallbacks.delete(t)}pushSubscriptionToInterface(t){let e=t.getKey("p256dh"),i=t.getKey("auth");if(!e||!i)throw new Error("Failed to get subscription keys");return{endpoint:t.endpoint,keys:{p256dh:this.arrayBufferToBase64(e),auth:this.arrayBufferToBase64(i)}}}async sendSubscriptionToServer(t){try{let e=await fetch("/api/push/subscribe",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(t)});if(!e.ok)throw new Error(`Server responded with ${e.status}: ${e.statusText}`);Y.log("subscription sent to server")}catch(e){throw Y.error("failed to send subscription to server:",e),e}}async removeSubscriptionFromServer(){try{let t=await fetch("/api/push/unsubscribe",{method:"POST",headers:{"Content-Type":"application/json"}});if(!t.ok)throw new Error(`Server responded with ${t.status}: ${t.statusText}`);Y.log("subscription removed from server")}catch(t){Y.error("failed to remove subscription from server:",t)}}urlBase64ToUint8Array(t){let e="=".repeat((4-t.length%4)%4),i=(t+e).replace(/-/g,"+").replace(/_/g,"/"),s=window.atob(i),o=new Uint8Array(s.length);for(let c=0;c<s.length;++c)o[c]=s.charCodeAt(c);return o}arrayBufferToBase64(t){let e=new Uint8Array(t),i="";for(let s=0;s<e.byteLength;s++)i+=String.fromCharCode(e[s]);return window.btoa(i)}async fetchVapidPublicKey(){try{let t=await fetch("/api/push/vapid-public-key",{headers:j.getAuthHeader()});if(!t.ok){if(t.status===503){Y.warn("Push notifications not configured on server"),this.pushNotificationsAvailable=!1;return}throw new Error(`Server responded with ${t.status}: ${t.statusText}`)}let e=await t.json();if(!e.publicKey||!e.enabled){Y.warn("Push notifications disabled on server"),this.pushNotificationsAvailable=!1;return}this.vapidPublicKey=e.publicKey,this.pushNotificationsAvailable=!0,vr=e.publicKey,Y.log("VAPID public key fetched from server"),Y.debug(`Public key: ${e.publicKey.substring(0,20)}...`)}catch(t){throw Y.error("Failed to fetch VAPID public key:",t),this.pushNotificationsAvailable=!1,t}}async getServerStatus(){try{let t=await fetch("/api/push/status");if(!t.ok)throw new Error(`Server responded with ${t.status}: ${t.statusText}`);return await t.json()}catch(t){throw Y.error("Failed to get server push status:",t),t}}async sendTestNotification(t){try{let e=await fetch("/api/push/test",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({message:t})});if(!e.ok)throw new Error(`Server responded with ${e.status}: ${e.statusText}`);let i=await e.json();Y.log("Test notification sent via server:",i)}catch(e){throw Y.error("Failed to send test notification via server:",e),e}}hasVapidKey(){return!!this.vapidPublicKey}getVapidPublicKey(){return this.vapidPublicKey}async refreshVapidConfig(){await this.fetchVapidPublicKey()}dispose(){this.permissionChangeCallbacks.clear(),this.subscriptionChangeCallbacks.clear(),this.initialized=!1,this.vapidPublicKey=null,this.pushNotificationsAvailable=!1}},ee=new Ti;Z();var he=N("offline-notification-manager"),br="vibetunnel-offline",yr=1,ve="notifications",Mi=class{constructor(){this.db=null;this.isOnline=navigator.onLine;this.processingQueue=!1;this.initialized=!1;this.initialize().catch(t=>{he.error("failed to initialize offline notification manager:",t)})}async initialize(){if(!this.initialized)try{await this.initializeDB(),this.setupOnlineListeners(),this.isOnline&&this.processQueue().catch(t=>{he.error("failed to process initial queue:",t)}),this.initialized=!0,he.log("offline notification manager initialized")}catch(t){throw he.error("failed to initialize offline notification manager:",t),t}}async initializeDB(){return new Promise((t,e)=>{let i=indexedDB.open(br,yr);i.onerror=()=>{e(new Error("Failed to open IndexedDB"))},i.onsuccess=()=>{this.db=i.result,t()},i.onupgradeneeded=s=>{let o=s.target.result;if(!o.objectStoreNames.contains(ve)){let c=o.createObjectStore(ve,{keyPath:"id"});c.createIndex("timestamp","timestamp"),c.createIndex("nextRetry","nextRetry")}}})}setupOnlineListeners(){window.addEventListener("online",()=>{he.log("connection restored, processing queued notifications"),this.isOnline=!0,this.processQueue().catch(t=>{he.error("failed to process queue after going online:",t)})}),window.addEventListener("offline",()=>{he.log("connection lost, queueing notifications"),this.isOnline=!1})}async queueNotification(t,e=3){if(!this.db)throw new Error("Database not initialized");let i={id:this.generateId(),timestamp:Date.now(),payload:t,retryCount:0,maxRetries:e,nextRetry:Date.now()};try{return await this.storeNotification(i),he.log("notification queued:",i.id),this.isOnline&&this.processQueue().catch(s=>{he.error("failed to process queue after queueing:",s)}),i.id}catch(s){throw he.error("failed to queue notification:",s),s}}async processQueue(){if(!(!this.db||this.processingQueue||!this.isOnline)){this.processingQueue=!0;try{let t=await this.getPendingNotifications();he.log(`processing ${t.length} queued notifications`);for(let e of t)try{await this.processNotification(e)}catch(i){he.error("failed to process notification:",e.id,i)}}catch(t){he.error("failed to process notification queue:",t)}finally{this.processingQueue=!1}}}async processNotification(t){try{(await navigator.serviceWorker.ready).active?.postMessage({type:"QUEUE_NOTIFICATION",payload:t.payload}),await this.removeNotification(t.id),he.log("notification processed successfully:",t.id)}catch(e){if(t.retryCount++,t.retryCount>=t.maxRetries)await this.removeNotification(t.id),he.warn("notification max retries reached, removing:",t.id);else{let i=2**t.retryCount*1e3;t.nextRetry=Date.now()+i,await this.updateNotification(t),he.log(`notification retry scheduled for ${new Date(t.nextRetry).toISOString()}:`,t.id)}throw e}}async getPendingNotifications(){if(!this.db)return[];let t=this.db;return new Promise((e,i)=>{let c=t.transaction([ve],"readonly").objectStore(ve).index("nextRetry"),r=IDBKeyRange.upperBound(Date.now()),a=c.getAll(r);a.onsuccess=()=>{e(a.result)},a.onerror=()=>{i(new Error("Failed to get pending notifications"))}})}async storeNotification(t){if(!this.db)throw new Error("Database not initialized");let e=this.db;return new Promise((i,s)=>{let r=e.transaction([ve],"readwrite").objectStore(ve).add(t);r.onsuccess=()=>i(),r.onerror=()=>s(new Error("Failed to store notification"))})}async updateNotification(t){if(!this.db)throw new Error("Database not initialized");let e=this.db;return new Promise((i,s)=>{let r=e.transaction([ve],"readwrite").objectStore(ve).put(t);r.onsuccess=()=>i(),r.onerror=()=>s(new Error("Failed to update notification"))})}async removeNotification(t){if(!this.db)throw new Error("Database not initialized");let e=this.db;return new Promise((i,s)=>{let r=e.transaction([ve],"readwrite").objectStore(ve).delete(t);r.onsuccess=()=>i(),r.onerror=()=>s(new Error("Failed to remove notification"))})}async getQueueStats(){if(!this.db)return{total:0,pending:0,failed:0,lastProcessed:0};let t=this.db;return new Promise((e,i)=>{let c=t.transaction([ve],"readonly").objectStore(ve).getAll();c.onsuccess=()=>{let r=c.result,a=Date.now(),g={total:r.length,pending:r.filter(m=>m.nextRetry<=a&&m.retryCount<m.maxRetries).length,failed:r.filter(m=>m.retryCount>=m.maxRetries).length,lastProcessed:Math.max(...r.map(m=>m.timestamp),0)};e(g)},c.onerror=()=>{i(new Error("Failed to get queue stats"))}})}async clearQueue(){if(!this.db)return;let t=this.db;return new Promise((e,i)=>{let c=t.transaction([ve],"readwrite").objectStore(ve).clear();c.onsuccess=()=>{he.log("notification queue cleared"),e()},c.onerror=()=>{i(new Error("Failed to clear queue"))}})}isDeviceOnline(){return this.isOnline}async forceProcessQueue(){this.isOnline&&await this.processQueue()}generateId(){return`${Date.now()}-${Math.random().toString(36).substr(2,9)}`}dispose(){this.db&&(this.db.close(),this.db=null),window.removeEventListener("online",this.processQueue),window.removeEventListener("offline",()=>{}),this.initialized=!1}},kn=new Mi;var jt=globalThis,Yt=jt.ShadowRoot&&(jt.ShadyCSS===void 0||jt.ShadyCSS.nativeShadow)&&"adoptedStyleSheets"in Document.prototype&&"replace"in CSSStyleSheet.prototype,Ai=Symbol(),as=new WeakMap,Ct=class{constructor(t,e,i){if(this._$cssResult$=!0,i!==Ai)throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");this.cssText=t,this.t=e}get styleSheet(){let t=this.o,e=this.t;if(Yt&&t===void 0){let i=e!==void 0&&e.length===1;i&&(t=as.get(e)),t===void 0&&((this.o=t=new CSSStyleSheet).replaceSync(this.cssText),i&&as.set(e,t))}return t}toString(){return this.cssText}},ls=h=>new Ct(typeof h=="string"?h:h+"",void 0,Ai),Et=(h,...t)=>{let e=h.length===1?h[0]:t.reduce((i,s,o)=>i+(c=>{if(c._$cssResult$===!0)return c.cssText;if(typeof c=="number")return c;throw Error("Value passed to 'css' function must be a 'css' function result: "+c+". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.")})(s)+h[o+1],h[0]);return new Ct(e,h,Ai)},cs=(h,t)=>{if(Yt)h.adoptedStyleSheets=t.map(e=>e instanceof CSSStyleSheet?e:e.styleSheet);else for(let e of t){let i=document.createElement("style"),s=jt.litNonce;s!==void 0&&i.setAttribute("nonce",s),i.textContent=e.cssText,h.appendChild(i)}},$i=Yt?h=>h:h=>h instanceof CSSStyleSheet?(t=>{let e="";for(let i of t.cssRules)e+=i.cssText;return ls(e)})(h):h;var{is:wr,defineProperty:_r,getOwnPropertyDescriptor:xr,getOwnPropertyNames:Sr,getOwnPropertySymbols:kr,getPrototypeOf:Cr}=Object,Ue=globalThis,hs=Ue.trustedTypes,Er=hs?hs.emptyScript:"",Tr=Ue.reactiveElementPolyfillSupport,Tt=(h,t)=>h,Mt={toAttribute(h,t){switch(t){case Boolean:h=h?Er:null;break;case Object:case Array:h=h==null?h:JSON.stringify(h)}return h},fromAttribute(h,t){let e=h;switch(t){case Boolean:e=h!==null;break;case Number:e=h===null?null:Number(h);break;case Object:case Array:try{e=JSON.parse(h)}catch{e=null}}return e}},Gt=(h,t)=>!wr(h,t),ds={attribute:!0,type:String,converter:Mt,reflect:!1,useDefault:!1,hasChanged:Gt};Symbol.metadata??(Symbol.metadata=Symbol("metadata")),Ue.litPropertyMetadata??(Ue.litPropertyMetadata=new WeakMap);var De=class extends HTMLElement{static addInitializer(t){this._$Ei(),(this.l??(this.l=[])).push(t)}static get observedAttributes(){return this.finalize(),this._$Eh&&[...this._$Eh.keys()]}static createProperty(t,e=ds){if(e.state&&(e.attribute=!1),this._$Ei(),this.prototype.hasOwnProperty(t)&&((e=Object.create(e)).wrapped=!0),this.elementProperties.set(t,e),!e.noAccessor){let i=Symbol(),s=this.getPropertyDescriptor(t,i,e);s!==void 0&&_r(this.prototype,t,s)}}static getPropertyDescriptor(t,e,i){let{get:s,set:o}=xr(this.prototype,t)??{get(){return this[e]},set(c){this[e]=c}};return{get:s,set(c){let r=s?.call(this);o?.call(this,c),this.requestUpdate(t,r,i)},configurable:!0,enumerable:!0}}static getPropertyOptions(t){return this.elementProperties.get(t)??ds}static _$Ei(){if(this.hasOwnProperty(Tt("elementProperties")))return;let t=Cr(this);t.finalize(),t.l!==void 0&&(this.l=[...t.l]),this.elementProperties=new Map(t.elementProperties)}static finalize(){if(this.hasOwnProperty(Tt("finalized")))return;if(this.finalized=!0,this._$Ei(),this.hasOwnProperty(Tt("properties"))){let e=this.properties,i=[...Sr(e),...kr(e)];for(let s of i)this.createProperty(s,e[s])}let t=this[Symbol.metadata];if(t!==null){let e=litPropertyMetadata.get(t);if(e!==void 0)for(let[i,s]of e)this.elementProperties.set(i,s)}this._$Eh=new Map;for(let[e,i]of this.elementProperties){let s=this._$Eu(e,i);s!==void 0&&this._$Eh.set(s,e)}this.elementStyles=this.finalizeStyles(this.styles)}static finalizeStyles(t){let e=[];if(Array.isArray(t)){let i=new Set(t.flat(1/0).reverse());for(let s of i)e.unshift($i(s))}else t!==void 0&&e.push($i(t));return e}static _$Eu(t,e){let i=e.attribute;return i===!1?void 0:typeof i=="string"?i:typeof t=="string"?t.toLowerCase():void 0}constructor(){super(),this._$Ep=void 0,this.isUpdatePending=!1,this.hasUpdated=!1,this._$Em=null,this._$Ev()}_$Ev(){this._$ES=new Promise(t=>this.enableUpdating=t),this._$AL=new Map,this._$E_(),this.requestUpdate(),this.constructor.l?.forEach(t=>t(this))}addController(t){(this._$EO??(this._$EO=new Set)).add(t),this.renderRoot!==void 0&&this.isConnected&&t.hostConnected?.()}removeController(t){this._$EO?.delete(t)}_$E_(){let t=new Map,e=this.constructor.elementProperties;for(let i of e.keys())this.hasOwnProperty(i)&&(t.set(i,this[i]),delete this[i]);t.size>0&&(this._$Ep=t)}createRenderRoot(){let t=this.shadowRoot??this.attachShadow(this.constructor.shadowRootOptions);return cs(t,this.constructor.elementStyles),t}connectedCallback(){this.renderRoot??(this.renderRoot=this.createRenderRoot()),this.enableUpdating(!0),this._$EO?.forEach(t=>t.hostConnected?.())}enableUpdating(t){}disconnectedCallback(){this._$EO?.forEach(t=>t.hostDisconnected?.())}attributeChangedCallback(t,e,i){this._$AK(t,i)}_$ET(t,e){let i=this.constructor.elementProperties.get(t),s=this.constructor._$Eu(t,i);if(s!==void 0&&i.reflect===!0){let o=(i.converter?.toAttribute!==void 0?i.converter:Mt).toAttribute(e,i.type);this._$Em=t,o==null?this.removeAttribute(s):this.setAttribute(s,o),this._$Em=null}}_$AK(t,e){let i=this.constructor,s=i._$Eh.get(t);if(s!==void 0&&this._$Em!==s){let o=i.getPropertyOptions(s),c=typeof o.converter=="function"?{fromAttribute:o.converter}:o.converter?.fromAttribute!==void 0?o.converter:Mt;this._$Em=s,this[s]=c.fromAttribute(e,o.type)??this._$Ej?.get(s)??null,this._$Em=null}}requestUpdate(t,e,i){if(t!==void 0){let s=this.constructor,o=this[t];if(i??(i=s.getPropertyOptions(t)),!((i.hasChanged??Gt)(o,e)||i.useDefault&&i.reflect&&o===this._$Ej?.get(t)&&!this.hasAttribute(s._$Eu(t,i))))return;this.C(t,e,i)}this.isUpdatePending===!1&&(this._$ES=this._$EP())}C(t,e,{useDefault:i,reflect:s,wrapped:o},c){i&&!(this._$Ej??(this._$Ej=new Map)).has(t)&&(this._$Ej.set(t,c??e??this[t]),o!==!0||c!==void 0)||(this._$AL.has(t)||(this.hasUpdated||i||(e=void 0),this._$AL.set(t,e)),s===!0&&this._$Em!==t&&(this._$Eq??(this._$Eq=new Set)).add(t))}async _$EP(){this.isUpdatePending=!0;try{await this._$ES}catch(e){Promise.reject(e)}let t=this.scheduleUpdate();return t!=null&&await t,!this.isUpdatePending}scheduleUpdate(){return this.performUpdate()}performUpdate(){if(!this.isUpdatePending)return;if(!this.hasUpdated){if(this.renderRoot??(this.renderRoot=this.createRenderRoot()),this._$Ep){for(let[s,o]of this._$Ep)this[s]=o;this._$Ep=void 0}let i=this.constructor.elementProperties;if(i.size>0)for(let[s,o]of i){let{wrapped:c}=o,r=this[s];c!==!0||this._$AL.has(s)||r===void 0||this.C(s,void 0,o,r)}}let t=!1,e=this._$AL;try{t=this.shouldUpdate(e),t?(this.willUpdate(e),this._$EO?.forEach(i=>i.hostUpdate?.()),this.update(e)):this._$EM()}catch(i){throw t=!1,this._$EM(),i}t&&this._$AE(e)}willUpdate(t){}_$AE(t){this._$EO?.forEach(e=>e.hostUpdated?.()),this.hasUpdated||(this.hasUpdated=!0,this.firstUpdated(t)),this.updated(t)}_$EM(){this._$AL=new Map,this.isUpdatePending=!1}get updateComplete(){return this.getUpdateComplete()}getUpdateComplete(){return this._$ES}shouldUpdate(t){return!0}update(t){this._$Eq&&(this._$Eq=this._$Eq.forEach(e=>this._$ET(e,this[e]))),this._$EM()}updated(t){}firstUpdated(t){}};De.elementStyles=[],De.shadowRootOptions={mode:"open"},De[Tt("elementProperties")]=new Map,De[Tt("finalized")]=new Map,Tr?.({ReactiveElement:De}),(Ue.reactiveElementVersions??(Ue.reactiveElementVersions=[])).push("2.1.0");var $t=globalThis,Xt=$t.trustedTypes,us=Xt?Xt.createPolicy("lit-html",{createHTML:h=>h}):void 0,Li="$lit$",Oe=`lit$${Math.random().toFixed(9).slice(2)}$`,Pi="?"+Oe,Mr=`<${Pi}>`,et=document,It=()=>et.createComment(""),Lt=h=>h===null||typeof h!="object"&&typeof h!="function",Ri=Array.isArray,bs=h=>Ri(h)||typeof h?.[Symbol.iterator]=="function",Ii=`[ 	
\f\r]`,At=/<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g,ps=/-->/g,fs=/>/g,Je=RegExp(`>|${Ii}(?:([^\\s"'>=/]+)(${Ii}*=${Ii}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`,"g"),gs=/'/g,ms=/"/g,ys=/^(?:script|style|textarea|title)$/i,Hi=h=>(t,...e)=>({_$litType$:h,strings:t,values:e}),S=Hi(1),$n=Hi(2),In=Hi(3),Fe=Symbol.for("lit-noChange"),re=Symbol.for("lit-nothing"),vs=new WeakMap,Ze=et.createTreeWalker(et,129);function ws(h,t){if(!Ri(h)||!h.hasOwnProperty("raw"))throw Error("invalid template strings array");return us!==void 0?us.createHTML(t):t}var _s=(h,t)=>{let e=h.length-1,i=[],s,o=t===2?"<svg>":t===3?"<math>":"",c=At;for(let r=0;r<e;r++){let a=h[r],g,m,l=-1,v=0;for(;v<a.length&&(c.lastIndex=v,m=c.exec(a),m!==null);)v=c.lastIndex,c===At?m[1]==="!--"?c=ps:m[1]!==void 0?c=fs:m[2]!==void 0?(ys.test(m[2])&&(s=RegExp("</"+m[2],"g")),c=Je):m[3]!==void 0&&(c=Je):c===Je?m[0]===">"?(c=s??At,l=-1):m[1]===void 0?l=-2:(l=c.lastIndex-m[2].length,g=m[1],c=m[3]===void 0?Je:m[3]==='"'?ms:gs):c===ms||c===gs?c=Je:c===ps||c===fs?c=At:(c=Je,s=void 0);let f=c===Je&&h[r+1].startsWith("/>")?" ":"";o+=c===At?a+Mr:l>=0?(i.push(g),a.slice(0,l)+Li+a.slice(l)+Oe+f):a+Oe+(l===-2?r:f)}return[ws(h,o+(h[e]||"<?>")+(t===2?"</svg>":t===3?"</math>":"")),i]},Pt=class h{constructor({strings:t,_$litType$:e},i){let s;this.parts=[];let o=0,c=0,r=t.length-1,a=this.parts,[g,m]=_s(t,e);if(this.el=h.createElement(g,i),Ze.currentNode=this.el.content,e===2||e===3){let l=this.el.content.firstChild;l.replaceWith(...l.childNodes)}for(;(s=Ze.nextNode())!==null&&a.length<r;){if(s.nodeType===1){if(s.hasAttributes())for(let l of s.getAttributeNames())if(l.endsWith(Li)){let v=m[c++],f=s.getAttribute(l).split(Oe),b=/([.?@])?(.*)/.exec(v);a.push({type:1,index:o,name:b[2],strings:f,ctor:b[1]==="."?Jt:b[1]==="?"?Zt:b[1]==="@"?ei:it}),s.removeAttribute(l)}else l.startsWith(Oe)&&(a.push({type:6,index:o}),s.removeAttribute(l));if(ys.test(s.tagName)){let l=s.textContent.split(Oe),v=l.length-1;if(v>0){s.textContent=Xt?Xt.emptyScript:"";for(let f=0;f<v;f++)s.append(l[f],It()),Ze.nextNode(),a.push({type:2,index:++o});s.append(l[v],It())}}}else if(s.nodeType===8)if(s.data===Pi)a.push({type:2,index:o});else{let l=-1;for(;(l=s.data.indexOf(Oe,l+1))!==-1;)a.push({type:7,index:o}),l+=Oe.length-1}o++}}static createElement(t,e){let i=et.createElement("template");return i.innerHTML=t,i}};function tt(h,t,e=h,i){if(t===Fe)return t;let s=i!==void 0?e._$Co?.[i]:e._$Cl,o=Lt(t)?void 0:t._$litDirective$;return s?.constructor!==o&&(s?._$AO?.(!1),o===void 0?s=void 0:(s=new o(h),s._$AT(h,e,i)),i!==void 0?(e._$Co??(e._$Co=[]))[i]=s:e._$Cl=s),s!==void 0&&(t=tt(h,s._$AS(h,t.values),s,i)),t}var Qt=class{constructor(t,e){this._$AV=[],this._$AN=void 0,this._$AD=t,this._$AM=e}get parentNode(){return this._$AM.parentNode}get _$AU(){return this._$AM._$AU}u(t){let{el:{content:e},parts:i}=this._$AD,s=(t?.creationScope??et).importNode(e,!0);Ze.currentNode=s;let o=Ze.nextNode(),c=0,r=0,a=i[0];for(;a!==void 0;){if(c===a.index){let g;a.type===2?g=new ut(o,o.nextSibling,this,t):a.type===1?g=new a.ctor(o,a.name,a.strings,this,t):a.type===6&&(g=new ti(o,this,t)),this._$AV.push(g),a=i[++r]}c!==a?.index&&(o=Ze.nextNode(),c++)}return Ze.currentNode=et,s}p(t){let e=0;for(let i of this._$AV)i!==void 0&&(i.strings!==void 0?(i._$AI(t,i,e),e+=i.strings.length-2):i._$AI(t[e])),e++}},ut=class h{get _$AU(){return this._$AM?._$AU??this._$Cv}constructor(t,e,i,s){this.type=2,this._$AH=re,this._$AN=void 0,this._$AA=t,this._$AB=e,this._$AM=i,this.options=s,this._$Cv=s?.isConnected??!0}get parentNode(){let t=this._$AA.parentNode,e=this._$AM;return e!==void 0&&t?.nodeType===11&&(t=e.parentNode),t}get startNode(){return this._$AA}get endNode(){return this._$AB}_$AI(t,e=this){t=tt(this,t,e),Lt(t)?t===re||t==null||t===""?(this._$AH!==re&&this._$AR(),this._$AH=re):t!==this._$AH&&t!==Fe&&this._(t):t._$litType$!==void 0?this.$(t):t.nodeType!==void 0?this.T(t):bs(t)?this.k(t):this._(t)}O(t){return this._$AA.parentNode.insertBefore(t,this._$AB)}T(t){this._$AH!==t&&(this._$AR(),this._$AH=this.O(t))}_(t){this._$AH!==re&&Lt(this._$AH)?this._$AA.nextSibling.data=t:this.T(et.createTextNode(t)),this._$AH=t}$(t){let{values:e,_$litType$:i}=t,s=typeof i=="number"?this._$AC(t):(i.el===void 0&&(i.el=Pt.createElement(ws(i.h,i.h[0]),this.options)),i);if(this._$AH?._$AD===s)this._$AH.p(e);else{let o=new Qt(s,this),c=o.u(this.options);o.p(e),this.T(c),this._$AH=o}}_$AC(t){let e=vs.get(t.strings);return e===void 0&&vs.set(t.strings,e=new Pt(t)),e}k(t){Ri(this._$AH)||(this._$AH=[],this._$AR());let e=this._$AH,i,s=0;for(let o of t)s===e.length?e.push(i=new h(this.O(It()),this.O(It()),this,this.options)):i=e[s],i._$AI(o),s++;s<e.length&&(this._$AR(i&&i._$AB.nextSibling,s),e.length=s)}_$AR(t=this._$AA.nextSibling,e){for(this._$AP?.(!1,!0,e);t&&t!==this._$AB;){let i=t.nextSibling;t.remove(),t=i}}setConnected(t){this._$AM===void 0&&(this._$Cv=t,this._$AP?.(t))}},it=class{get tagName(){return this.element.tagName}get _$AU(){return this._$AM._$AU}constructor(t,e,i,s,o){this.type=1,this._$AH=re,this._$AN=void 0,this.element=t,this.name=e,this._$AM=s,this.options=o,i.length>2||i[0]!==""||i[1]!==""?(this._$AH=Array(i.length-1).fill(new String),this.strings=i):this._$AH=re}_$AI(t,e=this,i,s){let o=this.strings,c=!1;if(o===void 0)t=tt(this,t,e,0),c=!Lt(t)||t!==this._$AH&&t!==Fe,c&&(this._$AH=t);else{let r=t,a,g;for(t=o[0],a=0;a<o.length-1;a++)g=tt(this,r[i+a],e,a),g===Fe&&(g=this._$AH[a]),c||(c=!Lt(g)||g!==this._$AH[a]),g===re?t=re:t!==re&&(t+=(g??"")+o[a+1]),this._$AH[a]=g}c&&!s&&this.j(t)}j(t){t===re?this.element.removeAttribute(this.name):this.element.setAttribute(this.name,t??"")}},Jt=class extends it{constructor(){super(...arguments),this.type=3}j(t){this.element[this.name]=t===re?void 0:t}},Zt=class extends it{constructor(){super(...arguments),this.type=4}j(t){this.element.toggleAttribute(this.name,!!t&&t!==re)}},ei=class extends it{constructor(t,e,i,s,o){super(t,e,i,s,o),this.type=5}_$AI(t,e=this){if((t=tt(this,t,e,0)??re)===Fe)return;let i=this._$AH,s=t===re&&i!==re||t.capture!==i.capture||t.once!==i.once||t.passive!==i.passive,o=t!==re&&(i===re||s);s&&this.element.removeEventListener(this.name,this,i),o&&this.element.addEventListener(this.name,this,t),this._$AH=t}handleEvent(t){typeof this._$AH=="function"?this._$AH.call(this.options?.host??this.element,t):this._$AH.handleEvent(t)}},ti=class{constructor(t,e,i){this.element=t,this.type=6,this._$AN=void 0,this._$AM=e,this.options=i}get _$AU(){return this._$AM._$AU}_$AI(t){tt(this,t)}},xs={M:Li,P:Oe,A:Pi,C:1,L:_s,R:Qt,D:bs,V:tt,I:ut,H:it,N:Zt,U:ei,B:Jt,F:ti},Ar=$t.litHtmlPolyfillSupport;Ar?.(Pt,ut),($t.litHtmlVersions??($t.litHtmlVersions=[])).push("3.3.0");var Ss=(h,t,e)=>{let i=e?.renderBefore??t,s=i._$litPart$;if(s===void 0){let o=e?.renderBefore??null;i._$litPart$=s=new ut(t.insertBefore(It(),o),o,void 0,e??{})}return s._$AI(h),s};var Rt=globalThis,F=class extends De{constructor(){super(...arguments),this.renderOptions={host:this},this._$Do=void 0}createRenderRoot(){var e;let t=super.createRenderRoot();return(e=this.renderOptions).renderBefore??(e.renderBefore=t.firstChild),t}update(t){let e=this.render();this.hasUpdated||(this.renderOptions.isConnected=this.isConnected),super.update(t),this._$Do=Ss(e,this.renderRoot,this.renderOptions)}connectedCallback(){super.connectedCallback(),this._$Do?.setConnected(!0)}disconnectedCallback(){super.disconnectedCallback(),this._$Do?.setConnected(!1)}render(){return Fe}};F._$litElement$=!0,F.finalized=!0,Rt.litElementHydrateSupport?.({LitElement:F});var $r=Rt.litElementPolyfillSupport;$r?.({LitElement:F});(Rt.litElementVersions??(Rt.litElementVersions=[])).push("4.2.0");var z=h=>(t,e)=>{e!==void 0?e.addInitializer(()=>{customElements.define(h,t)}):customElements.define(h,t)};var Ir={attribute:!0,type:String,converter:Mt,reflect:!1,hasChanged:Gt},Lr=(h=Ir,t,e)=>{let{kind:i,metadata:s}=e,o=globalThis.litPropertyMetadata.get(s);if(o===void 0&&globalThis.litPropertyMetadata.set(s,o=new Map),i==="setter"&&((h=Object.create(h)).wrapped=!0),o.set(e.name,h),i==="accessor"){let{name:c}=e;return{set(r){let a=t.get.call(this);t.set.call(this,r),this.requestUpdate(c,a,h)},init(r){return r!==void 0&&this.C(c,void 0,h,r),r}}}if(i==="setter"){let{name:c}=e;return function(r){let a=this[c];t.call(this,r),this.requestUpdate(c,a,h)}}throw Error("Unsupported decorator location: "+i)};function $(h){return(t,e)=>typeof e=="object"?Lr(h,t,e):((i,s,o)=>{let c=s.hasOwnProperty(o);return s.constructor.createProperty(o,i),c?Object.getOwnPropertyDescriptor(s,o):void 0})(h,t,e)}function A(h){return $({...h,state:!0,attribute:!1})}var si={ATTRIBUTE:1,CHILD:2,PROPERTY:3,BOOLEAN_ATTRIBUTE:4,EVENT:5,ELEMENT:6},st=h=>(...t)=>({_$litDirective$:h,values:t}),We=class{constructor(t){}get _$AU(){return this._$AM._$AU}_$AT(t,e,i){this._$Ct=t,this._$AM=e,this._$Ci=i}_$AS(t,e){return this.update(t,e)}update(t,e){return this.render(...e)}};var{I:Pr}=xs;var Cs=h=>h.strings===void 0,ks=()=>document.createComment(""),pt=(h,t,e)=>{let i=h._$AA.parentNode,s=t===void 0?h._$AB:t._$AA;if(e===void 0){let o=i.insertBefore(ks(),s),c=i.insertBefore(ks(),s);e=new Pr(o,c,h,h.options)}else{let o=e._$AB.nextSibling,c=e._$AM,r=c!==h;if(r){let a;e._$AQ?.(h),e._$AM=h,e._$AP!==void 0&&(a=h._$AU)!==c._$AU&&e._$AP(a)}if(o!==s||r){let a=e._$AA;for(;a!==o;){let g=a.nextSibling;i.insertBefore(a,s),a=g}}}return e},qe=(h,t,e=h)=>(h._$AI(t,e),h),Rr={},ri=(h,t=Rr)=>h._$AH=t,Es=h=>h._$AH,ni=h=>{h._$AP?.(!1,!0);let t=h._$AA,e=h._$AB.nextSibling;for(;t!==e;){let i=t.nextSibling;t.remove(),t=i}};var Ts=st(class extends We{constructor(){super(...arguments),this.key=re}render(h,t){return this.key=h,t}update(h,[t,e]){return t!==this.key&&(ri(h),this.key=t),e}});var Re={MOBILE:768,TABLET:1024,DESKTOP:1280},Ve={DEFAULT_WIDTH:320,MIN_WIDTH:240,MAX_WIDTH:600,MOBILE_RIGHT_MARGIN:80},Bi={SIDEBAR:200,MOBILE_SLIDE:200,RESIZE_HANDLE:200},Ms={MOBILE_OVERLAY:20,SIDEBAR_MOBILE:30,SESSION_EXITED_OVERLAY:100};var je={AUTO_REFRESH_INTERVAL:1e3,SESSION_SEARCH_DELAY:500,KILL_ALL_ANIMATION_DELAY:500,ERROR_MESSAGE_TIMEOUT:5e3,SUCCESS_MESSAGE_TIMEOUT:5e3,KILL_ALL_BUTTON_DISABLE_DURATION:2e3};Z();var Di=class{constructor(){this.callbacks=new Set;this.resizeObserver=null;this.currentState=this.getMediaQueryState();try{this.resizeObserver=new ResizeObserver(()=>{try{let t=this.getMediaQueryState();this.hasStateChanged(this.currentState,t)&&(this.currentState=t,this.notifyCallbacks(t))}catch(t){console.error("Error in ResizeObserver callback:",t)}}),this.resizeObserver.observe(document.documentElement)}catch(t){console.error("Failed to initialize ResizeObserver:",t),this.setupFallbackResizeListener()}}setupFallbackResizeListener(){let t,e=()=>{clearTimeout(t),t=window.setTimeout(()=>{let i=this.getMediaQueryState();this.hasStateChanged(this.currentState,i)&&(this.currentState=i,this.notifyCallbacks(i))},100)};window.addEventListener("resize",e)}getMediaQueryState(){let t=window.innerWidth;return{isMobile:t<Re.MOBILE,isTablet:t>=Re.MOBILE&&t<Re.DESKTOP,isDesktop:t>=Re.DESKTOP}}hasStateChanged(t,e){return t.isMobile!==e.isMobile||t.isTablet!==e.isTablet||t.isDesktop!==e.isDesktop}notifyCallbacks(t){this.callbacks.forEach(e=>e(t))}subscribe(t){return this.callbacks.add(t),t(this.currentState),()=>{this.callbacks.delete(t)}}getCurrentState(){return{...this.currentState}}destroy(){this.resizeObserver&&this.resizeObserver.disconnect(),this.callbacks.clear()}},Ye=new Di;Z();var As=N("terminal-utils");function Oi(h,t){requestAnimationFrame(()=>{let i=(t||document).querySelector("vibe-terminal");i?.fitTerminal?(As.debug(`triggering terminal resize for session ${h}`),i.fitTerminal()):As.warn(`terminal not found or fitTerminal method unavailable for session ${h}`)})}var oi=null,Fi=[];function ai(){let t=new URL(window.location.href).searchParams.get("session");t&&t!==oi?(oi=t,setTimeout(()=>{let e=document.querySelectorAll("session-card, .sidebar, [data-session-id], .session-name, h1, h2"),i=null;for(let s of e){let o=s.textContent?.trim()||"";if(s.hasAttribute("data-session-name")){i=s.getAttribute("data-session-name");break}if(o&&!o.includes("/")&&o.length>0&&o.length<100&&!o.startsWith("~")&&!o.startsWith("/")){i=o.split(`
`)[0];break}}i?document.title=`${i} - VibeTunnel`:document.title="Session - VibeTunnel"},500)):!t&&oi&&(oi=null,setTimeout(()=>{let e=document.querySelectorAll("session-card").length;document.title=e>0?`VibeTunnel - ${e} Session${e!==1?"s":""}`:"VibeTunnel"},100))}function $s(){Hr(),ai();let h=null,t=new MutationObserver(()=>{h&&clearTimeout(h),h=setTimeout(ai,100)});t.observe(document.body,{childList:!0,subtree:!0,characterData:!0});let e=()=>ai();window.addEventListener("popstate",e);let i=setInterval(ai,2e3);Fi=[()=>t.disconnect(),()=>window.removeEventListener("popstate",e),()=>clearInterval(i),()=>{h&&clearTimeout(h)}]}function Hr(){Fi.forEach(h=>h()),Fi=[]}var Is="1.0.0-beta.6";var ft=class extends F{constructor(){super(...arguments);this.size=24}render(){return S`
      <img
        src="/apple-touch-icon.png"
        alt="VibeTunnel"
        style="width: ${this.size}px; height: ${this.size}px"
        class="terminal-icon"
      />
    `}};ft.styles=Et`
    :host {
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }

    svg {
      display: block;
      width: var(--icon-size, 24px);
      height: var(--icon-size, 24px);
    }

    .terminal-icon {
      border-radius: 20%;
      box-shadow:
        0 2px 8px rgba(0, 0, 0, 0.3),
        0 1px 3px rgba(0, 0, 0, 0.2);
      background: rgba(255, 255, 255, 0.05);
      padding: 2px;
    }
  `,_([$({type:Number})],ft.prototype,"size",2),ft=_([z("terminal-icon")],ft);Z();var Uo=N("notification-status"),rt=class extends F{constructor(){super(...arguments);this.permission="default";this.subscription=null;this.isSupported=!1}createRenderRoot(){return this}connectedCallback(){super.connectedCallback(),this.initializeComponent()}disconnectedCallback(){super.disconnectedCallback(),this.permissionChangeUnsubscribe&&this.permissionChangeUnsubscribe(),this.subscriptionChangeUnsubscribe&&this.subscriptionChangeUnsubscribe()}async initializeComponent(){this.isSupported=ee.isSupported(),this.isSupported&&(await ee.waitForInitialization(),this.permission=ee.getPermission(),this.subscription=ee.getSubscription(),this.permissionChangeUnsubscribe=ee.onPermissionChange(e=>{this.permission=e}),this.subscriptionChangeUnsubscribe=ee.onSubscriptionChange(e=>{this.subscription=e}))}handleClick(){this.dispatchEvent(new CustomEvent("open-settings"))}getStatusConfig(){if(this.permission==="granted"&&this.subscription)return{color:"text-status-success",tooltip:"Notifications enabled"};let e="Notifications disabled";return this.isSupported?this.permission==="denied"?e="Notifications blocked":this.subscription||(e="Notifications not subscribed"):e="Notifications not supported",{color:"text-status-error",tooltip:e}}renderIcon(){return S`
      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M15 17h5l-3.5-3.5A7 7 0 0 1 17 10a7 7 0 0 0-14 0 7 7 0 0 1 .5 3.5L0 17h5m10 0v1a3 3 0 0 1-6 0v-1m6 0H9"
        />
      </svg>
    `}render(){let{color:e,tooltip:i}=this.getStatusConfig();return S`
      <button
        @click=${this.handleClick}
        class="p-2 ${e} hover:text-dark-text transition-colors relative"
        title="${i}"
      >
        ${this.renderIcon()}
      </button>
    `}};_([A()],rt.prototype,"permission",2),_([A()],rt.prototype,"subscription",2),_([A()],rt.prototype,"isSupported",2),rt=_([z("notification-status")],rt);var Ee=class extends F{constructor(){super(...arguments);this.sessions=[];this.hideExited=!0;this.currentUser=null;this.authMethod=null;this.killingAll=!1;this.showUserMenu=!1;this.handleClickOutside=e=>{e.target.closest(".user-menu-container")||(this.showUserMenu=!1)}}createRenderRoot(){return this}get runningSessions(){return this.sessions.filter(e=>e.status==="running")}get exitedSessions(){return this.sessions.filter(e=>e.status==="exited")}handleCreateSession(e){let s=e.currentTarget.getBoundingClientRect();document.documentElement.style.setProperty("--vt-button-x",`${s.left+s.width/2}px`),document.documentElement.style.setProperty("--vt-button-y",`${s.top+s.height/2}px`),document.documentElement.style.setProperty("--vt-button-width",`${s.width}px`),document.documentElement.style.setProperty("--vt-button-height",`${s.height}px`),this.dispatchEvent(new CustomEvent("create-session"))}handleKillAll(){this.killingAll||(this.killingAll=!0,this.requestUpdate(),this.dispatchEvent(new CustomEvent("kill-all-sessions")),window.setTimeout(()=>{this.killingAll=!1},je.KILL_ALL_BUTTON_DISABLE_DURATION))}handleCleanExited(){this.dispatchEvent(new CustomEvent("clean-exited-sessions"))}handleHideExitedToggle(){this.dispatchEvent(new CustomEvent("hide-exited-change",{detail:!this.hideExited}))}handleOpenFileBrowser(){this.dispatchEvent(new CustomEvent("open-file-browser"))}handleOpenSettings(){console.log("\u{1F527} HeaderBase: handleOpenSettings called"),this.showUserMenu=!1,this.dispatchEvent(new CustomEvent("open-settings"))}handleLogout(){this.showUserMenu=!1,this.dispatchEvent(new CustomEvent("logout"))}toggleUserMenu(){this.showUserMenu=!this.showUserMenu}handleHomeClick(){this.dispatchEvent(new CustomEvent("navigate-to-list"))}connectedCallback(){super.connectedCallback(),document.addEventListener("click",this.handleClickOutside)}disconnectedCallback(){super.disconnectedCallback(),document.removeEventListener("click",this.handleClickOutside)}};_([$({type:Array})],Ee.prototype,"sessions",2),_([$({type:Boolean})],Ee.prototype,"hideExited",2),_([$({type:String})],Ee.prototype,"currentUser",2),_([$({type:String})],Ee.prototype,"authMethod",2),_([A()],Ee.prototype,"killingAll",2),_([A()],Ee.prototype,"showUserMenu",2);var li=class extends Ee{render(){let t=this.runningSessions;return S`
      <div
        class="app-header sidebar-header bg-dark-bg-secondary border-b border-dark-border p-3"
        style="padding-top: max(0.75rem, calc(0.75rem + env(safe-area-inset-top)));"
      >
        <!-- Compact layout for sidebar -->
        <div class="flex items-center justify-between">
          <!-- Title and logo -->
          <button
            class="flex items-center gap-2 hover:opacity-80 transition-opacity cursor-pointer group"
            title="Go to home"
            @click=${this.handleHomeClick}
          >
            <terminal-icon size="20"></terminal-icon>
            <div class="min-w-0">
              <h1
                class="text-sm font-bold text-accent-green font-mono group-hover:underline truncate"
              >
                VibeTunnel
              </h1>
              <p class="text-dark-text-muted text-xs font-mono">
                ${t.length} ${t.length===1?"session":"sessions"}
              </p>
            </div>
          </button>
          
          <!-- Action buttons group -->
          <div class="flex items-center gap-1">
            <!-- Notification button -->
            <notification-status
              @open-settings=${()=>this.dispatchEvent(new CustomEvent("open-settings"))}
            ></notification-status>
            
            <!-- Create Session button -->
            <button
              class="p-2 text-accent-green border border-accent-green hover:bg-accent-green hover:text-dark-bg rounded-lg transition-all duration-200 flex-shrink-0"
              @click=${this.handleCreateSession}
              title="Create New Session"
            >
              <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                <path d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z"/>
              </svg>
            </button>
            
            <!-- User menu -->
            ${this.renderCompactUserMenu()}
          </div>
        </div>
      </div>
    `}renderCompactUserMenu(){return this.currentUser?S`
      <div class="user-menu-container relative">
        <button
          class="font-mono text-xs px-2 py-1 text-dark-text-muted hover:text-dark-text rounded border border-dark-border hover:bg-dark-bg-tertiary transition-all duration-200"
          @click=${this.toggleUserMenu}
          title="User menu"
        >
          <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
            <path
              d="M10 0C4.48 0 0 4.48 0 10s4.48 10 10 10 10-4.48 10-10S15.52 0 10 0zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z"
            />
          </svg>
        </button>
        ${this.showUserMenu?S`
              <div
                class="absolute right-0 top-full mt-1 bg-dark-surface border border-dark-border rounded-lg shadow-lg py-1 z-50 min-w-32"
              >
                <div
                  class="px-3 py-1.5 text-xs text-dark-text-muted border-b border-dark-border font-mono"
                >
                  ${this.currentUser}
                </div>
                <button
                  class="w-full text-left px-3 py-1.5 text-xs font-mono text-status-warning hover:bg-dark-bg-secondary hover:text-status-error"
                  @click=${this.handleLogout}
                >
                  Logout
                </button>
              </div>
            `:""}
      </div>
    `:S``}};li=_([z("sidebar-header")],li);var ci=class extends Ee{render(){let t=this.runningSessions;return S`
      <div
        class="app-header bg-dark-bg-secondary border-b border-dark-border p-3"
        style="padding-top: max(0.75rem, calc(0.75rem + env(safe-area-inset-top)));"
      >
        <div class="flex items-center justify-between">
          <button
            class="flex items-center gap-2 hover:opacity-80 transition-opacity cursor-pointer group"
            title="Go to home"
            @click=${this.handleHomeClick}
          >
            <terminal-icon size="24"></terminal-icon>
            <div class="flex items-baseline gap-2">
              <h1 class="text-xl font-bold text-accent-green font-mono group-hover:underline">
                VibeTunnel
              </h1>
              <p class="text-dark-text-muted text-xs font-mono">
                (${t.length})
              </p>
            </div>
          </button>

          <div class="flex items-center gap-2">
            <notification-status
              @open-settings=${()=>this.dispatchEvent(new CustomEvent("open-settings"))}
            ></notification-status>
            <button
              class="p-2 text-dark-text border border-dark-border hover:border-accent-green hover:text-accent-green rounded-lg transition-all duration-200"
              @click=${()=>this.dispatchEvent(new CustomEvent("open-file-browser"))}
              title="Browse Files (⌘O)"
            >
              <svg width="20" height="20" viewBox="0 0 16 16" fill="currentColor">
                <path
                  d="M1.75 1h5.5c.966 0 1.75.784 1.75 1.75v1h4c.966 0 1.75.784 1.75 1.75v7.75A1.75 1.75 0 0113 15H3a1.75 1.75 0 01-1.75-1.75V2.75C1.25 1.784 1.784 1 1.75 1zM2.75 2.5v10.75c0 .138.112.25.25.25h10a.25.25 0 00.25-.25V5.5a.25.25 0 00-.25-.25H8.75v-2.5a.25.25 0 00-.25-.25h-5.5a.25.25 0 00-.25.25z"
                />
              </svg>
            </button>
            <button
              class="p-2 bg-accent-green text-dark-bg hover:bg-accent-green-light rounded-lg transition-all duration-200 vt-create-button"
              @click=${this.handleCreateSession}
              title="Create New Session"
              data-testid="create-session-button"
            >
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <path d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z"/>
              </svg>
            </button>
            ${this.renderUserMenu()}
          </div>
        </div>
      </div>
    `}renderUserMenu(){return this.currentUser?S`
      <div class="user-menu-container relative flex-shrink-0">
        <button
          class="font-mono text-sm px-3 py-2 text-dark-text border border-dark-border hover:bg-dark-bg-tertiary hover:text-dark-text rounded-lg transition-all duration-200 flex items-center gap-2"
          @click=${this.toggleUserMenu}
          title="User menu"
        >
          <span class="hidden sm:inline">${this.currentUser}</span>
          <svg
            width="20"
            height="20"
            viewBox="0 0 20 20"
            fill="currentColor"
            class="sm:hidden"
          >
            <path d="M10 9a3 3 0 100-6 3 3 0 000 6zM3 18a7 7 0 1114 0H3z" />
          </svg>
          <svg
            width="10"
            height="10"
            viewBox="0 0 10 10"
            fill="currentColor"
            class="transition-transform ${this.showUserMenu?"rotate-180":""}"
          >
            <path d="M5 7L1 3h8z" />
          </svg>
        </button>
        ${this.showUserMenu?S`
              <div
                class="absolute right-0 top-full mt-1 bg-dark-surface border border-dark-border rounded-lg shadow-lg py-1 z-50 min-w-36"
              >
                <div class="px-3 py-2 text-sm text-dark-text-muted border-b border-dark-border">
                  ${this.authMethod||"authenticated"}
                </div>
                <button
                  class="w-full text-left px-3 py-2 text-sm font-mono text-status-warning hover:bg-dark-bg-secondary hover:text-status-error"
                  @click=${this.handleLogout}
                >
                  Logout
                </button>
              </div>
            `:""}
      </div>
    `:S``}};ci=_([z("full-header")],ci);var Ne=class extends F{constructor(){super(...arguments);this.sessions=[];this.hideExited=!0;this.showSplitView=!1;this.currentUser=null;this.authMethod=null;this.forwardEvent=e=>{this.dispatchEvent(new CustomEvent(e.type,{detail:e.detail,bubbles:!0}))}}createRenderRoot(){return this}render(){return this.showSplitView?this.renderSidebarHeader():this.renderFullHeader()}renderSidebarHeader(){return S`
      <sidebar-header
        .sessions=${this.sessions}
        .hideExited=${this.hideExited}
        .currentUser=${this.currentUser}
        .authMethod=${this.authMethod}
        @create-session=${this.forwardEvent}
        @hide-exited-change=${this.forwardEvent}
        @kill-all-sessions=${this.forwardEvent}
        @clean-exited-sessions=${this.forwardEvent}
        @open-settings=${this.forwardEvent}
        @logout=${this.forwardEvent}
        @navigate-to-list=${this.forwardEvent}
      ></sidebar-header>
    `}renderFullHeader(){return S`
      <full-header
        .sessions=${this.sessions}
        .hideExited=${this.hideExited}
        .currentUser=${this.currentUser}
        .authMethod=${this.authMethod}
        @create-session=${this.forwardEvent}
        @hide-exited-change=${this.forwardEvent}
        @kill-all-sessions=${this.forwardEvent}
        @clean-exited-sessions=${this.forwardEvent}
        @open-file-browser=${this.forwardEvent}
        @open-settings=${this.forwardEvent}
        @logout=${this.forwardEvent}
        @navigate-to-list=${this.forwardEvent}
      ></full-header>
    `}};_([$({type:Array})],Ne.prototype,"sessions",2),_([$({type:Boolean})],Ne.prototype,"hideExited",2),_([$({type:Boolean})],Ne.prototype,"showSplitView",2),_([$({type:String})],Ne.prototype,"currentUser",2),_([$({type:String})],Ne.prototype,"authMethod",2),Ne=_([z("app-header")],Ne);var Ht=(h,t)=>{let e=h._$AN;if(e===void 0)return!1;for(let i of e)i._$AO?.(t,!1),Ht(i,t);return!0},hi=h=>{let t,e;do{if((t=h._$AM)===void 0)break;e=t._$AN,e.delete(h),h=t}while(e?.size===0)},Ls=h=>{for(let t;t=h._$AM;h=t){let e=t._$AN;if(e===void 0)t._$AN=e=new Set;else if(e.has(h))break;e.add(h),Or(t)}};function Br(h){this._$AN!==void 0?(hi(this),this._$AM=h,Ls(this)):this._$AM=h}function Dr(h,t=!1,e=0){let i=this._$AH,s=this._$AN;if(s!==void 0&&s.size!==0)if(t)if(Array.isArray(i))for(let o=e;o<i.length;o++)Ht(i[o],!1),hi(i[o]);else i!=null&&(Ht(i,!1),hi(i));else Ht(this,h)}var Or=h=>{h.type==si.CHILD&&(h._$AP??(h._$AP=Dr),h._$AQ??(h._$AQ=Br))},di=class extends We{constructor(){super(...arguments),this._$AN=void 0}_$AT(t,e,i){super._$AT(t,e,i),Ls(this),this.isConnected=t._$AU}_$AO(t,e=!0){t!==this.isConnected&&(this.isConnected=t,t?this.reconnected?.():this.disconnected?.()),e&&(Ht(this,t),hi(this))}setValue(t){if(Cs(this._$Ct))this._$Ct._$AI(t,this);else{let e=[...this._$Ct._$AH];e[this._$Ci]=t,this._$Ct._$AI(e,this,0)}}disconnected(){}reconnected(){}};var Bt=()=>new zi,zi=class{},Ni=new WeakMap,gt=st(class extends di{render(h){return re}update(h,[t]){let e=t!==this.G;return e&&this.G!==void 0&&this.rt(void 0),(e||this.lt!==this.ct)&&(this.G=t,this.ht=h.options?.host,this.rt(this.ct=h.element)),re}rt(h){if(this.isConnected||(h=void 0),typeof this.G=="function"){let t=this.ht??globalThis,e=Ni.get(t);e===void 0&&(e=new WeakMap,Ni.set(t,e)),e.get(this.G)!==void 0&&this.G.call(this.ht,void 0),e.set(this.G,h),h!==void 0&&this.G.call(this.ht,h)}else this.G.value=h}get lt(){return typeof this.G=="function"?Ni.get(this.ht??globalThis)?.get(this.G):this.G?.value}disconnected(){this.lt===this.ct&&this.rt(void 0)}reconnected(){this.rt(this.ct)}});Pe();function Ki(h,t){if(t==="directory")return S`
      <svg class="w-5 h-5 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
        <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
      </svg>
    `;let e=h.split(".").pop()?.toLowerCase();return{js:S`<svg class="w-5 h-5 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 4a2 2 0 00-2 2v8a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2H4zm6 3a1 1 0 011 1v2a1 1 0 11-2 0V9h-.5a.5.5 0 000 1H10a1 1 0 110 2H8.5A2.5 2.5 0 016 9.5V8a1 1 0 011-1h3z"
      />
    </svg>`,mjs:S`<svg class="w-5 h-5 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 4a2 2 0 00-2 2v8a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2H4zm6 3a1 1 0 011 1v2a1 1 0 11-2 0V9h-.5a.5.5 0 000 1H10a1 1 0 110 2H8.5A2.5 2.5 0 016 9.5V8a1 1 0 011-1h3z"
      />
    </svg>`,cjs:S`<svg class="w-5 h-5 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 4a2 2 0 00-2 2v8a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2H4zm6 3a1 1 0 011 1v2a1 1 0 11-2 0V9h-.5a.5.5 0 000 1H10a1 1 0 110 2H8.5A2.5 2.5 0 016 9.5V8a1 1 0 011-1h3z"
      />
    </svg>`,ts:S`<svg class="w-5 h-5 text-blue-500" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 4a2 2 0 00-2 2v8a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2H4zm6 3h4v1h-1v4a1 1 0 11-2 0V8h-1a1 1 0 110-2zM6 7h2v6H6V7z"
      />
    </svg>`,tsx:S`<svg class="w-5 h-5 text-blue-500" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 4a2 2 0 00-2 2v8a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2H4zm6 3h4v1h-1v4a1 1 0 11-2 0V8h-1a1 1 0 110-2zM6 7h2v6H6V7z"
      />
    </svg>`,jsx:S`<svg class="w-5 h-5 text-cyan-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 4a2 2 0 00-2 2v8a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2H4zm2 6a2 2 0 114 0 2 2 0 01-4 0zm6-2a2 2 0 104 0 2 2 0 00-4 0z"
      />
    </svg>`,html:S`<svg class="w-5 h-5 text-orange-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm1 2h10v2H5V5zm0 4h10v2H5V9zm0 4h6v2H5v-2z"
      />
    </svg>`,htm:S`<svg class="w-5 h-5 text-orange-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm1 2h10v2H5V5zm0 4h10v2H5V9zm0 4h6v2H5v-2z"
      />
    </svg>`,css:S`<svg class="w-5 h-5 text-pink-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm4 6a2 2 0 100 4 2 2 0 000-4zm4-2a2 2 0 100 4 2 2 0 000-4z"
      />
    </svg>`,scss:S`<svg class="w-5 h-5 text-pink-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm4 6a2 2 0 100 4 2 2 0 000-4zm4-2a2 2 0 100 4 2 2 0 000-4z"
      />
    </svg>`,sass:S`<svg class="w-5 h-5 text-pink-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm4 6a2 2 0 100 4 2 2 0 000-4zm4-2a2 2 0 100 4 2 2 0 000-4z"
      />
    </svg>`,less:S`<svg class="w-5 h-5 text-pink-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm4 6a2 2 0 100 4 2 2 0 000-4zm4-2a2 2 0 100 4 2 2 0 000-4z"
      />
    </svg>`,json:S`<svg class="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"
      />
    </svg>`,jsonc:S`<svg class="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"
      />
    </svg>`,xml:S`<svg class="w-5 h-5 text-purple-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"
      />
    </svg>`,yaml:S`<svg class="w-5 h-5 text-purple-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"
      />
    </svg>`,yml:S`<svg class="w-5 h-5 text-purple-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"
      />
    </svg>`,md:S`<svg class="w-5 h-5 text-gray-300" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M2 6a2 2 0 012-2h12a2 2 0 012 2v8a2 2 0 01-2 2H4a2 2 0 01-2-2V6zm2 0v8h12V6H4zm2 2h8v1H6V8zm0 2h8v1H6v-1zm0 2h6v1H6v-1z"
      />
    </svg>`,markdown:S`<svg class="w-5 h-5 text-gray-300" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M2 6a2 2 0 012-2h12a2 2 0 012 2v8a2 2 0 01-2 2H4a2 2 0 01-2-2V6zm2 0v8h12V6H4zm2 2h8v1H6V8zm0 2h8v1H6v-1zm0 2h6v1H6v-1z"
      />
    </svg>`,txt:S`<svg class="w-5 h-5 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm0 2h12v10H4V5zm2 2v6h8V7H6zm2 1h4v1H8V8zm0 2h4v1H8v-1z"
      />
    </svg>`,text:S`<svg class="w-5 h-5 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm0 2h12v10H4V5zm2 2v6h8V7H6zm2 1h4v1H8V8zm0 2h4v1H8v-1z"
      />
    </svg>`,png:S`<svg class="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        fill-rule="evenodd"
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z"
        clip-rule="evenodd"
      />
    </svg>`,jpg:S`<svg class="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        fill-rule="evenodd"
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z"
        clip-rule="evenodd"
      />
    </svg>`,jpeg:S`<svg class="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        fill-rule="evenodd"
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z"
        clip-rule="evenodd"
      />
    </svg>`,gif:S`<svg class="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        fill-rule="evenodd"
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z"
        clip-rule="evenodd"
      />
    </svg>`,webp:S`<svg class="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        fill-rule="evenodd"
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z"
        clip-rule="evenodd"
      />
    </svg>`,bmp:S`<svg class="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        fill-rule="evenodd"
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z"
        clip-rule="evenodd"
      />
    </svg>`,svg:S`<svg class="w-5 h-5 text-indigo-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm6 6L8 7l2 2 2-2-2 2 2 2-2-2-2 2 2-2z"
      />
    </svg>`,zip:S`<svg class="w-5 h-5 text-amber-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"
      />
    </svg>`,tar:S`<svg class="w-5 h-5 text-amber-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"
      />
    </svg>`,gz:S`<svg class="w-5 h-5 text-amber-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"
      />
    </svg>`,rar:S`<svg class="w-5 h-5 text-amber-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"
      />
    </svg>`,"7z":S`<svg class="w-5 h-5 text-amber-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"
      />
    </svg>`,pdf:S`<svg class="w-5 h-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
      <path d="M4 18h12V6h-4V2H4v16zm8-14v4h4l-4-4zM6 10h8v1H6v-1zm0 2h8v1H6v-1zm0 2h6v1H6v-1z" />
    </svg>`,sh:S`<svg class="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 000 2h11.586l-2.293 2.293a1 1 0 101.414 1.414L17.414 6H19a1 1 0 100-2H3zM3 11a1 1 0 100 2h3.586l-2.293 2.293a1 1 0 101.414 1.414L9.414 13H11a1 1 0 100-2H3z"
      />
    </svg>`,bash:S`<svg class="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 000 2h11.586l-2.293 2.293a1 1 0 101.414 1.414L17.414 6H19a1 1 0 100-2H3zM3 11a1 1 0 100 2h3.586l-2.293 2.293a1 1 0 101.414 1.414L9.414 13H11a1 1 0 100-2H3z"
      />
    </svg>`,zsh:S`<svg class="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 000 2h11.586l-2.293 2.293a1 1 0 101.414 1.414L17.414 6H19a1 1 0 100-2H3zM3 11a1 1 0 100 2h3.586l-2.293 2.293a1 1 0 101.414 1.414L9.414 13H11a1 1 0 100-2H3z"
      />
    </svg>`,fish:S`<svg class="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 000 2h11.586l-2.293 2.293a1 1 0 101.414 1.414L17.414 6H19a1 1 0 100-2H3zM3 11a1 1 0 100 2h3.586l-2.293 2.293a1 1 0 101.414 1.414L9.414 13H11a1 1 0 100-2H3z"
      />
    </svg>`}[e||""]||Fr()}function Fr(){return S`
    <svg class="w-5 h-5 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        fill-rule="evenodd"
        d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 6a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm1 3a1 1 0 100 2h6a1 1 0 100-2H7z"
        clip-rule="evenodd"
      />
    </svg>
  `}function Ps(){return S`
    <svg class="w-5 h-5 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        fill-rule="evenodd"
        d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z"
        clip-rule="evenodd"
      />
    </svg>
  `}function Ui(h){if(!h||h==="unchanged")return"";let t={modified:"M",added:"A",deleted:"D",untracked:"?",unchanged:""};return S`
    <span class="text-xs px-1.5 py-0.5 rounded font-bold ${{modified:"bg-yellow-900/50 text-yellow-400",added:"bg-green-900/50 text-green-400",deleted:"bg-red-900/50 text-red-400",untracked:"bg-gray-700 text-gray-400",unchanged:""}[h]}">
      ${t[h]}
    </span>
  `}var ui={close:S`
    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        stroke-width="2"
        d="M6 18L18 6M6 6l12 12"
      ></path>
    </svg>
  `,folder:S`
    <svg class="w-6 h-6 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
      <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
    </svg>
  `,git:S`
    <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 16 16">
      <path
        fill-rule="evenodd"
        d="M11.75 2.5a.75.75 0 100 1.5.75.75 0 000-1.5zm-2.25.75a2.25 2.25 0 113 2.122V6A2.5 2.5 0 0110 8.5H6a1 1 0 00-1 1v1.128a2.251 2.251 0 11-1.5 0V5.372a2.25 2.25 0 111.5 0v1.836A2.492 2.492 0 016 7h4a1 1 0 001-1v-.628A2.25 2.25 0 019.5 3.25zM4.25 12a.75.75 0 100 1.5.75.75 0 000-1.5zM3.5 3.25a.75.75 0 111.5 0 .75.75 0 01-1.5 0z"
      />
    </svg>
  `,preview:S`
    <svg class="w-16 h-16 mb-4 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        fill-rule="evenodd"
        d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 6a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm1 3a1 1 0 100 2h6a1 1 0 100-2H7z"
        clip-rule="evenodd"
      />
    </svg>
  `,binary:S`
    <svg class="w-16 h-16 mb-4 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
      <path
        d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"
      />
    </svg>
  `};Z();var Nr=/^(?:\/Users\/[^/]+|\/home\/[^/]+|[A-Za-z]:[/\\]Users[/\\][^/\\]+|\/root)/;function nt(h){return h?h.replace(Nr,"~"):""}async function mt(h){try{return await navigator.clipboard.writeText(h),!0}catch{let e=document.createElement("textarea");e.value=h,e.style.position="fixed",e.style.left="-999999px",e.style.top="-999999px",document.body.appendChild(e),e.focus(),e.select();try{let i=document.execCommand("copy");return document.body.removeChild(e),i}catch{return document.body.removeChild(e),!1}}}Z();var vt=N("monaco-editor"),ue=class extends F{constructor(){super(...arguments);this.content="";this.originalContent="";this.modifiedContent="";this.language="";this.filename="";this.readOnly=!1;this.mode="normal";this.showModeToggle=!1;this.options={};this.isLoading=!0;this.diffMode="sideBySide";this.containerWidth=0;this.containerRef=Bt();this.editor=null;this.resizeObserver=null;this.monacoLoaded=!1}createRenderRoot(){return this}async connectedCallback(){super.connectedCallback(),await this.loadMonaco(),this.setupResizeObserver(),await this.updateComplete,this.containerRef.value&&!this.editor&&!this.isLoading&&await this.createEditor()}disconnectedCallback(){super.disconnectedCallback(),this.disposeEditor(),this.resizeObserver&&(this.resizeObserver.disconnect(),this.resizeObserver=null)}async loadMonaco(){if(this.monacoLoaded||window.monaco){this.monacoLoaded=!0,this.isLoading=!1;return}try{vt.debug("Loading Monaco Editor..."),await Vt(),this.monacoLoaded=!0,this.isLoading=!1,vt.debug("Monaco Editor loaded successfully")}catch(e){vt.error("Failed to load Monaco Editor:",e),this.isLoading=!1}}async waitForMonaco(e=1e4){let i=Date.now();for(;!window.monaco;){if(Date.now()-i>e)throw new Error("Monaco Editor failed to load within timeout");await new Promise(s=>setTimeout(s,100))}}setupResizeObserver(){this.resizeObserver=new ResizeObserver(e=>{for(let i of e){if(this.containerWidth=i.contentRect.width,this.mode==="diff"&&this.editor){let o=this.containerWidth<768?"inline":"sideBySide";o!==this.diffMode&&(this.diffMode=o,this.recreateEditor())}this.editor&&this.editor.layout()}}),this.containerRef.value&&this.resizeObserver.observe(this.containerRef.value)}async updated(e){super.updated(e),(e.has("mode")||e.has("content")&&!this.editor||e.has("originalContent")&&this.mode==="diff"||e.has("modifiedContent")&&this.mode==="diff")&&!this.isLoading&&this.containerRef.value?await this.recreateEditor():this.editor&&!this.isLoading&&(e.has("content")&&this.mode==="normal"&&this.updateContent(),(e.has("language")||e.has("filename"))&&this.updateLanguage(),e.has("readOnly")&&this.updateReadOnly())}async recreateEditor(){this.disposeEditor(),await this.createEditor()}async createEditor(){if(!(!this.containerRef.value||!window.monaco))try{this.setupTheme();let e={theme:"vs-dark",automaticLayout:!0,fontSize:14,fontFamily:"'Fira Code', Menlo, Monaco, 'Courier New', monospace",fontLigatures:!0,minimap:{enabled:!1},scrollBeyondLastLine:!1,renderWhitespace:"selection",readOnly:this.readOnly,folding:!0,foldingStrategy:"indentation",foldingHighlight:!0,showFoldingControls:"always",renderLineHighlight:"all",renderLineHighlightOnlyWhenFocus:!1,...this.options};if(this.mode==="diff"){let i={readOnly:!0,automaticLayout:!0,scrollBeyondLastLine:!1,minimap:{enabled:!1},renderWhitespace:"selection",renderSideBySide:this.diffMode==="sideBySide",ignoreTrimWhitespace:!1};this.editor=window.monaco.editor.createDiffEditor(this.containerRef.value,i);let s=this.detectLanguage(),o=Date.now(),c=`${this.filename||"untitled"}-${o}`,r=window.monaco.editor.createModel(this.originalContent||"",s,window.monaco.Uri.parse(`file:///${c}#original`)),a=window.monaco.editor.createModel(this.modifiedContent||"",s,window.monaco.Uri.parse(`file:///${c}#modified`));vt.debug("Creating diff editor");let g=this.editor;g.setModel({original:r,modified:a});let m=()=>{this.editor&&this.editor.layout()},l=g.onDidUpdateDiff(()=>{m(),l.dispose()});setTimeout(m,200)}else this.editor=window.monaco.editor.create(this.containerRef.value,{...e,value:this.content,language:this.detectLanguage()}),this.readOnly||(this.editor.addCommand(window.monaco.KeyMod.CtrlCmd|window.monaco.KeyCode.KeyS,()=>{this.handleSave()}),this.editor.onDidChangeModelContent(()=>{let i=this.editor?.getValue()||"";this.dispatchEvent(new CustomEvent("content-changed",{detail:{content:i},bubbles:!0,composed:!0}))}));vt.debug(`Created ${this.mode} editor`)}catch(e){vt.error("Failed to create editor:",e)}}setupTheme(){window.monaco&&window.monaco.editor.setTheme("vs-dark")}detectLanguage(){if(this.language)return this.language;if(this.filename){let e=this.filename.split(".").pop()?.toLowerCase();return{js:"javascript",jsx:"javascript",ts:"typescript",tsx:"typescript",json:"json",html:"html",htm:"html",css:"css",scss:"scss",sass:"sass",less:"less",py:"python",rb:"ruby",go:"go",rs:"rust",java:"java",c:"c",cpp:"cpp",cs:"csharp",php:"php",swift:"swift",kt:"kotlin",scala:"scala",r:"r",sql:"sql",sh:"shell",bash:"shell",zsh:"shell",fish:"shell",ps1:"powershell",yml:"yaml",yaml:"yaml",xml:"xml",md:"markdown",markdown:"markdown",dockerfile:"dockerfile",makefile:"makefile",gitignore:"gitignore"}[e||""]||"plaintext"}return"plaintext"}updateContent(){if(!this.editor||this.mode==="diff")return;this.editor.getValue()!==this.content&&this.editor.setValue(this.content)}updateLanguage(){if(!this.editor||!window.monaco)return;let e=this.detectLanguage();if(this.mode==="normal"){let i=this.editor.getModel();i&&window.monaco.editor.setModelLanguage(i,e)}else{let i=this.editor,s=i.getOriginalEditor().getModel(),o=i.getModifiedEditor().getModel();s&&window.monaco.editor.setModelLanguage(s,e),o&&window.monaco.editor.setModelLanguage(o,e)}}updateReadOnly(){this.editor&&(this.mode==="normal"?this.editor.updateOptions({readOnly:this.readOnly}):this.editor.getModifiedEditor().updateOptions({readOnly:this.readOnly}))}handleSave(){if(this.readOnly||!this.editor||this.mode==="diff")return;let e=this.editor.getValue();this.dispatchEvent(new CustomEvent("save",{detail:{content:e},bubbles:!0,composed:!0}))}toggleDiffMode(){if(this.mode!=="diff")return;this.diffMode=this.diffMode==="inline"?"sideBySide":"inline";let e="",i="";if(this.editor){let o=this.editor.getModel();o&&(e=o.original?.getValue()||this.originalContent||"",i=o.modified?.getValue()||this.modifiedContent||"")}this.originalContent=e,this.modifiedContent=i,this.recreateEditor()}disposeEditor(){if(this.editor){if(this.mode==="diff"){let e=this.editor,i=e.getModel();e.setModel(null),i&&setTimeout(()=>{i.original?.dispose(),i.modified?.dispose()},0)}this.editor.dispose(),this.editor=null}}render(){return S`
      <div
        class="monaco-editor-root"
        style="display: block; width: 100%; height: 100%; position: relative;"
      >
        <div
          class="editor-container"
          ${gt(this.containerRef)}
          style="width: 100%; height: 100%; position: relative; background: #1e1e1e;"
        >
          ${this.isLoading?S`
                <div
                  class="loading"
                  style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: #666; font-family: ui-monospace, monospace;"
                >
                  Loading editor...
                </div>
              `:""}
          ${this.showModeToggle&&this.mode==="diff"&&!this.isLoading?S`
                <button
                  class="mode-toggle"
                  style="position: absolute; top: 10px; right: 10px; z-index: 10; background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.2); color: #fff; padding: 4px 8px; border-radius: 4px; font-size: 12px; cursor: pointer;"
                  @click=${this.toggleDiffMode}
                  title="Toggle between inline and side-by-side diff"
                  @mouseenter=${e=>{let i=e.target;i.style.background="rgba(255, 255, 255, 0.2)",i.style.borderColor="rgba(255, 255, 255, 0.3)"}}
                  @mouseleave=${e=>{let i=e.target;i.style.background="rgba(255, 255, 255, 0.1)",i.style.borderColor="rgba(255, 255, 255, 0.2)"}}
                >
                  ${this.diffMode==="inline"?"Side by Side":"Inline"}
                </button>
              `:""}
        </div>
      </div>
    `}};_([$({type:String})],ue.prototype,"content",2),_([$({type:String})],ue.prototype,"originalContent",2),_([$({type:String})],ue.prototype,"modifiedContent",2),_([$({type:String})],ue.prototype,"language",2),_([$({type:String})],ue.prototype,"filename",2),_([$({type:Boolean})],ue.prototype,"readOnly",2),_([$({type:String})],ue.prototype,"mode",2),_([$({type:Boolean})],ue.prototype,"showModeToggle",2),_([$({type:Object})],ue.prototype,"options",2),_([A()],ue.prototype,"isLoading",2),_([A()],ue.prototype,"diffMode",2),_([A()],ue.prototype,"containerWidth",2),ue=_([z("monaco-editor")],ue);var fe=N("file-browser"),te=class extends F{constructor(){super(...arguments);this.visible=!1;this.mode="browse";this.session=null;this.currentPath="";this.currentFullPath="";this.files=[];this.loading=!1;this.selectedFile=null;this.preview=null;this.diff=null;this.diffContent=null;this.gitFilter="all";this.showHidden=!1;this.gitStatus=null;this.previewLoading=!1;this.showDiff=!1;this.errorMessage="";this.mobileView="list";this.isMobile=window.innerWidth<768;this.editingPath=!1;this.pathInputValue="";this.editorRef=Bt();this.pathInputRef=Bt();this.noAuthMode=!1;this.handleKeyDown=e=>{this.visible&&(e.key==="Escape"?(e.preventDefault(),this.editingPath?this.cancelPathEdit():this.handleCancel()):e.key==="Enter"&&this.selectedFile&&this.selectedFile.type==="file"&&!this.editingPath?(e.preventDefault(),this.insertPathIntoTerminal()):(e.metaKey||e.ctrlKey)&&e.key==="c"&&this.selectedFile&&(e.preventDefault(),this.handleCopyToClipboard(this.selectedFile.path)))};this.handleResize=()=>{this.isMobile=window.innerWidth<768,!this.isMobile&&this.mobileView==="preview"&&(this.mobileView="list")};this.touchStartX=0;this.touchStartY=0}createRenderRoot(){return this}async connectedCallback(){super.connectedCallback(),await this.checkAuthConfig(),this.visible&&(this.currentPath=this.session?.workingDir||".",await this.loadDirectory(this.currentPath)),document.addEventListener("keydown",this.handleKeyDown),window.addEventListener("resize",this.handleResize),this.setupTouchHandlers()}async updated(e){super.updated(e),(e.has("visible")||e.has("session"))&&this.visible&&(this.currentPath=this.session?.workingDir||".",await this.loadDirectory(this.currentPath))}async loadDirectory(e){this.loading=!0;try{let s=`/api/fs/browse?${new URLSearchParams({path:e,showHidden:this.showHidden.toString(),gitFilter:this.gitFilter})}`;fe.debug(`loading directory: ${e}`),fe.debug(`fetching URL: ${s}`);let o=this.noAuthMode?{}:{...j.getAuthHeader()},c=await fetch(s,{headers:o});if(fe.debug(`response status: ${c.status}`),c.ok){let r=await c.json();fe.debug(`received ${r.files?.length||0} files`),this.currentPath=r.path,this.currentFullPath=r.fullPath,this.files=r.files||[],this.gitStatus=r.gitStatus,this.errorMessage=""}else{let r="Failed to load directory";try{r=(await c.json()).error||r}catch{r=`Failed to load directory (${c.status})`}fe.error(`failed to load directory: ${c.status}`,new Error(r)),this.showErrorMessage(r)}}catch(i){fe.error("error loading directory:",i),this.showErrorMessage("Network error loading directory")}finally{this.loading=!1}}async loadPreview(e){if(e.type!=="directory"){this.previewLoading=!0,this.selectedFile=e,this.showDiff=!1;try{fe.debug(`loading preview for file: ${e.name}`),fe.debug(`file path: ${e.path}`);let i=this.noAuthMode?{}:{...j.getAuthHeader()},s=await fetch(`/api/fs/preview?path=${encodeURIComponent(e.path)}`,{headers:i});s.ok?(this.preview=await s.json(),this.requestUpdate()):fe.error(`preview failed: ${s.status}`,new Error(await s.text()))}catch(i){fe.error("error loading preview:",i)}finally{this.previewLoading=!1}}}async loadDiff(e){if(!(e.type==="directory"||!e.gitStatus||e.gitStatus==="unchanged")){this.previewLoading=!0,this.showDiff=!0;try{let i=this.noAuthMode?{}:{...j.getAuthHeader()},[s,o]=await Promise.all([fetch(`/api/fs/diff?path=${encodeURIComponent(e.path)}`,{headers:i}),fetch(`/api/fs/diff-content?path=${encodeURIComponent(e.path)}`,{headers:i})]);s.ok&&(this.diff=await s.json()),o.ok&&(this.diffContent=await o.json())}catch(i){fe.error("error loading diff:",i)}finally{this.previewLoading=!1}}}handleFileClick(e){e.type==="directory"?this.loadDirectory(e.path):(this.selectedFile=e,this.isMobile&&(this.mobileView="preview"),this.gitFilter==="changed"&&e.gitStatus&&e.gitStatus!=="unchanged"?this.loadDiff(e):this.loadPreview(e))}async handleCopyToClipboard(e){await mt(e)?fe.debug(`copied to clipboard: ${e}`):fe.error("failed to copy to clipboard")}insertPathIntoTerminal(){if(!this.selectedFile)return;let e;this.currentFullPath&&this.selectedFile.name?e=this.currentFullPath.endsWith("/")?this.currentFullPath+this.selectedFile.name:`${this.currentFullPath}/${this.selectedFile.name}`:e=this.selectedFile.path,this.dispatchEvent(new CustomEvent("insert-path",{detail:{path:e,type:this.selectedFile.type},bubbles:!0,composed:!0})),this.dispatchEvent(new CustomEvent("browser-cancel"))}showErrorMessage(e){this.errorMessage=e,setTimeout(()=>{this.errorMessage=""},5e3)}handleParentClick(){let e;if(this.currentFullPath!=="/"){if(this.currentFullPath){let i=this.currentFullPath.split("/").filter(s=>s!=="");i.length===0?e="/":(i.pop(),e=i.length===0?"/":`/${i.join("/")}`)}else{let i=this.currentPath.split("/").filter(s=>s!=="");i.length<=1?e="/":(i.pop(),e=`/${i.join("/")}`)}this.loadDirectory(e)}}toggleGitFilter(){this.gitFilter=this.gitFilter==="all"?"changed":"all",this.loadDirectory(this.currentPath)}toggleHidden(){this.showHidden=!this.showHidden,this.loadDirectory(this.currentPath)}toggleDiff(){this.selectedFile?.gitStatus&&this.selectedFile.gitStatus!=="unchanged"&&(this.showDiff?this.loadPreview(this.selectedFile):this.loadDiff(this.selectedFile))}handleSelect(){this.mode==="select"&&this.currentPath&&this.dispatchEvent(new CustomEvent("directory-selected",{detail:this.currentPath}))}handleCancel(){this.dispatchEvent(new CustomEvent("browser-cancel"))}handleOverlayClick(e){e.target===e.currentTarget&&this.handleCancel()}renderPreview(){if(this.previewLoading)return S`
        <div class="flex items-center justify-center h-full text-dark-text-muted">
          Loading preview...
        </div>
      `;if(this.showDiff&&this.diff)return this.renderDiff();if(!this.preview)return S`
        <div class="flex flex-col items-center justify-center h-full text-dark-text-muted">
          ${ui.preview}
          <div>Select a file to preview</div>
        </div>
      `;switch(this.preview.type){case"image":return S`
          <div class="flex items-center justify-center p-4 h-full">
            <img
              src="${this.preview.url}"
              alt="${this.selectedFile?.name}"
              class="max-w-full max-h-full object-contain rounded"
            />
          </div>
        `;case"text":return S`
          <monaco-editor
            ${gt(this.editorRef)}
            .content=${this.preview.content||""}
            .language=${this.preview.language||""}
            .filename=${this.selectedFile?.name||""}
            .readOnly=${!0}
            mode="normal"
            class="h-full w-full"
          ></monaco-editor>
        `;case"binary":return S`
          <div class="flex flex-col items-center justify-center h-full text-dark-text-muted">
            ${ui.binary}
            <div class="text-lg mb-2">Binary File</div>
            <div class="text-sm">${this.preview.humanSize||`${this.preview.size} bytes`}</div>
            <div class="text-sm text-dark-text-muted mt-2">
              ${this.preview.mimeType||"Unknown type"}
            </div>
          </div>
        `}}renderDiff(){if(!this.diffContent&&(!this.diff||!this.diff.diff))return S`
        <div class="flex items-center justify-center h-full text-dark-text-muted">
          No changes in this file
        </div>
      `;if(this.diffContent)return S`
        <monaco-editor
          ${gt(this.editorRef)}
          .originalContent=${this.diffContent.originalContent||""}
          .modifiedContent=${this.diffContent.modifiedContent||""}
          .language=${this.diffContent.language||""}
          .filename=${this.selectedFile?.name||""}
          .readOnly=${!0}
          mode="diff"
          .showModeToggle=${!0}
          class="h-full w-full"
        ></monaco-editor>
      `;if(!this.diff)return S``;let e=this.diff.diff.split(`
`);return S`
      <div class="overflow-auto h-full p-4 font-mono text-xs">
        ${e.map(i=>{let s="text-dark-text-muted";return i.startsWith("+")?s="text-status-success bg-green-900/20":i.startsWith("-")?s="text-status-error bg-red-900/20":i.startsWith("@@")&&(s="text-accent-blue font-semibold"),S`<div class="whitespace-pre ${s}">${i}</div>`})}
      </div>
    `}render(){return this.visible?S`
      <div class="fixed inset-0 bg-dark-bg z-50 flex flex-col" @click=${this.handleOverlayClick}>
        ${this.isMobile&&this.mobileView==="preview"?S`
              <div class="absolute top-1/2 left-2 -translate-y-1/2 text-dark-text-muted opacity-50">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M11 19l-7-7 7-7m8 14l-7-7 7-7"
                  ></path>
                </svg>
              </div>
            `:""}
        <div
          class="w-full h-full bg-dark-bg flex flex-col overflow-hidden"
          @click=${e=>e.stopPropagation()}
        >
          <!-- Compact Header (like session-view) -->
          <div
            class="flex items-center justify-between px-3 py-2 border-b border-dark-border text-sm min-w-0 bg-dark-bg-secondary"
            style="padding-top: max(0.5rem, env(safe-area-inset-top)); padding-left: max(0.75rem, env(safe-area-inset-left)); padding-right: max(0.75rem, env(safe-area-inset-right));"
          >
            <div class="flex items-center gap-3 min-w-0 flex-1">
              <button
                class="text-dark-text-muted hover:text-dark-text font-mono text-xs px-2 py-1 flex-shrink-0 transition-colors flex items-center gap-1"
                @click=${this.handleCancel}
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M15 19l-7-7 7-7"
                  ></path>
                </svg>
                <span>Back</span>
              </button>
              <div class="text-dark-text min-w-0 flex-1 overflow-hidden">
                ${this.editingPath?S`
                      <input
                        ${gt(this.pathInputRef)}
                        type="text"
                        .value=${this.pathInputValue}
                        @input=${this.handlePathInput}
                        @keydown=${this.handlePathKeyDown}
                        @blur=${this.handlePathBlur}
                        class="bg-dark-bg border border-dark-border rounded px-2 py-1 text-blue-400 text-xs sm:text-sm font-mono w-full min-w-0 focus:outline-none focus:border-accent-green"
                        placeholder="Enter path and press Enter"
                      />
                    `:S`
                      <div
                        class="text-blue-400 text-xs sm:text-sm overflow-hidden text-ellipsis whitespace-nowrap font-mono cursor-pointer hover:bg-dark-bg-lighter rounded px-1 py-1 -mx-1"
                        title="${this.currentFullPath||this.currentPath||"File Browser"} (click to edit)"
                        @click=${this.handlePathClick}
                      >
                        ${nt(this.currentFullPath||this.currentPath||"File Browser")}
                      </div>
                    `}
              </div>
            </div>
            <div class="flex items-center gap-2 text-xs flex-shrink-0 ml-2">
              ${this.errorMessage?S`
                    <div
                      class="bg-red-500/20 border border-red-500 text-red-400 px-2 py-1 rounded text-xs"
                    >
                      ${this.errorMessage}
                    </div>
                  `:""}
            </div>
          </div>

          <!-- Main content -->
          <div class="flex-1 flex overflow-hidden">
            <!-- File list -->
            <div
              class="${this.isMobile&&this.mobileView==="preview"?"hidden":""} ${this.isMobile?"w-full":"w-80"} bg-dark-bg-secondary border-r border-dark-border flex flex-col"
            >
              <!-- File list header with toggles -->
              <div
                class="bg-dark-bg-secondary border-b border-dark-border p-3 flex items-center justify-between"
              >
                <div class="flex gap-2">
                  <button
                    class="btn-secondary text-xs px-2 py-1 font-mono ${this.gitFilter==="changed"?"bg-accent-green text-dark-bg":""}"
                    @click=${this.toggleGitFilter}
                    title="Show only Git changes"
                  >
                    Git Changes
                  </button>
                  <button
                    class="btn-secondary text-xs px-2 py-1 font-mono ${this.showHidden?"bg-accent-green text-dark-bg":""}"
                    @click=${this.toggleHidden}
                    title="Show hidden files"
                  >
                    Hidden Files
                  </button>
                </div>
                ${this.gitStatus?.branch?S`
                      <span class="text-dark-text-muted text-xs flex items-center gap-1 font-mono">
                        ${ui.git} ${this.gitStatus.branch}
                      </span>
                    `:""}
              </div>

              <!-- File list content -->
              <div
                class="flex-1 overflow-y-auto overflow-x-auto scrollbar-thin scrollbar-thumb-white/20 scrollbar-track-transparent hover:scrollbar-thumb-white/30"
              >
                ${this.loading?S`
                      <div class="flex items-center justify-center h-full text-dark-text-muted">
                        Loading...
                      </div>
                    `:S`
                      ${this.currentFullPath!=="/"?S`
                            <div
                              class="p-3 hover:bg-dark-bg-lighter cursor-pointer transition-colors flex items-center gap-2 border-b border-dark-border"
                              @click=${this.handleParentClick}
                            >
                              ${Ps()}
                              <span class="text-dark-text-muted">..</span>
                            </div>
                          `:""}
                      ${this.files.map(e=>S`
                          <div
                            class="p-3 hover:bg-dark-bg-lighter cursor-pointer transition-colors flex items-center gap-2 
                            ${this.selectedFile?.path===e.path?"bg-dark-bg-lighter border-l-2 border-accent-green":""}"
                            @click=${()=>this.handleFileClick(e)}
                          >
                            <span class="flex-shrink-0 relative">
                              ${Ki(e.name,e.type)}
                              ${e.isSymlink?S`
                                    <svg
                                      class="w-3 h-3 text-dark-text-muted absolute -bottom-1 -right-1"
                                      fill="currentColor"
                                      viewBox="0 0 20 20"
                                    >
                                      <path
                                        fill-rule="evenodd"
                                        d="M12.586 4.586a2 2 0 112.828 2.828l-3 3a2 2 0 01-2.828 0 1 1 0 00-1.414 1.414 4 4 0 005.656 0l3-3a4 4 0 00-5.656-5.656l-1.5 1.5a1 1 0 101.414 1.414l1.5-1.5zm-5 5a2 2 0 012.828 0 1 1 0 101.414-1.414 4 4 0 00-5.656 0l-3 3a4 4 0 105.656 5.656l1.5-1.5a1 1 0 10-1.414-1.414l-1.5 1.5a2 2 0 11-2.828-2.828l3-3z"
                                        clip-rule="evenodd"
                                      />
                                    </svg>
                                  `:""}
                            </span>
                            <span
                              class="flex-1 text-sm whitespace-nowrap ${e.type==="directory"?"text-accent-blue":"text-dark-text"}"
                              title="${e.name}${e.isSymlink?" (symlink)":""}"
                              >${e.name}</span
                            >
                            <span class="flex-shrink-0"
                              >${Ui(e.gitStatus)}</span
                            >
                          </div>
                        `)}
                    `}
              </div>
            </div>

            <!-- Preview pane -->
            <div
              class="${this.isMobile&&this.mobileView==="list"?"hidden":""} ${this.isMobile?"w-full":"flex-1"} bg-dark-bg flex flex-col overflow-hidden"
            >
              ${this.selectedFile?S`
                    <div
                      class="bg-dark-bg-secondary border-b border-dark-border p-3 ${this.isMobile?"space-y-2":"flex items-center justify-between"}"
                    >
                      <div class="flex items-center gap-2 ${this.isMobile?"min-w-0":""}">
                        ${this.isMobile?S`
                              <button
                                @click=${()=>{this.mobileView="list"}}
                                class="text-dark-text-muted hover:text-dark-text transition-colors flex-shrink-0"
                                title="Back to files"
                              >
                                <svg
                                  class="w-5 h-5"
                                  fill="none"
                                  stroke="currentColor"
                                  viewBox="0 0 24 24"
                                >
                                  <path
                                    stroke-linecap="round"
                                    stroke-linejoin="round"
                                    stroke-width="2"
                                    d="M15 19l-7-7 7-7"
                                  ></path>
                                </svg>
                              </button>
                            `:""}
                        <span class="flex-shrink-0 relative"
                          >${Ki(this.selectedFile.name,this.selectedFile.type)}
                          ${this.selectedFile.isSymlink?S`
                                <svg
                                  class="w-3 h-3 text-dark-text-muted absolute -bottom-1 -right-1"
                                  fill="currentColor"
                                  viewBox="0 0 20 20"
                                >
                                  <path
                                    fill-rule="evenodd"
                                    d="M12.586 4.586a2 2 0 112.828 2.828l-3 3a2 2 0 01-2.828 0 1 1 0 00-1.414 1.414 4 4 0 005.656 0l3-3a4 4 0 00-5.656-5.656l-1.5 1.5a1 1 0 101.414 1.414l1.5-1.5zm-5 5a2 2 0 012.828 0 1 1 0 101.414-1.414 4 4 0 00-5.656 0l-3 3a4 4 0 105.656 5.656l1.5-1.5a1 1 0 10-1.414-1.414l-1.5 1.5a2 2 0 11-2.828-2.828l3-3z"
                                    clip-rule="evenodd"
                                  />
                                </svg>
                              `:""}
                        </span>
                        <span class="font-mono text-sm ${this.isMobile?"truncate":""}"
                          >${this.selectedFile.name}${this.selectedFile.isSymlink?" \u2192":""}</span
                        >
                        ${Ui(this.selectedFile.gitStatus)}
                      </div>
                      <div
                        class="${this.isMobile?"grid grid-cols-2 gap-2":"flex gap-2 flex-shrink-0"}"
                      >
                        ${this.selectedFile.type==="file"?S`
                              <button
                                class="btn-secondary text-xs px-2 py-1 font-mono"
                                @click=${()=>this.selectedFile&&this.handleCopyToClipboard(this.selectedFile.path)}
                                title="Copy path to clipboard (⌘C)"
                              >
                                Copy Path
                              </button>
                              ${this.mode==="browse"?S`
                                    <button
                                      class="btn-primary text-xs px-2 py-1 font-mono"
                                      @click=${this.insertPathIntoTerminal}
                                      title="Insert path into terminal (Enter)"
                                    >
                                      Insert Path
                                    </button>
                                  `:""}
                            `:""}
                        ${this.selectedFile.gitStatus&&this.selectedFile.gitStatus!=="unchanged"?S`
                              <button
                                class="btn-secondary text-xs px-2 py-1 font-mono ${this.showDiff?"bg-accent-green text-dark-bg":""} ${this.isMobile&&this.selectedFile.type==="file"&&this.mode==="browse"?"":"col-span-2"}"
                                @click=${this.toggleDiff}
                              >
                                ${this.showDiff?"View File":"View Diff"}
                              </button>
                            `:""}
                      </div>
                    </div>
                  `:""}
              <div class="flex-1 overflow-hidden">${this.renderPreview()}</div>
            </div>
          </div>

          ${this.mode==="select"?S`
                <div class="p-4 border-t border-dark-border flex gap-4">
                  <button class="btn-ghost font-mono flex-1" @click=${this.handleCancel}>
                    Cancel
                  </button>
                  <button class="btn-primary font-mono flex-1" @click=${this.handleSelect}>
                    Select Directory
                  </button>
                </div>
              `:""}
        </div>
      </div>
    `:S``}disconnectedCallback(){super.disconnectedCallback(),document.removeEventListener("keydown",this.handleKeyDown),window.removeEventListener("resize",this.handleResize),this.removeTouchHandlers()}async checkAuthConfig(){try{let e=await fetch("/api/auth/config");if(e.ok){let i=await e.json();this.noAuthMode=i.noAuth===!0,fe.debug("Auth config:",i)}}catch(e){fe.error("Failed to fetch auth config:",e)}}setupTouchHandlers(){if(!this.isMobile)return;let e=s=>{this.touchStartX=s.touches[0].clientX,this.touchStartY=s.touches[0].clientY},i=s=>{if(!this.visible||!this.isMobile)return;let o=s.changedTouches[0].clientX-this.touchStartX,c=Math.abs(s.changedTouches[0].clientY-this.touchStartY);Math.abs(o)>50&&c<50&&o>0&&(this.mobileView==="preview"?this.mobileView="list":this.handleCancel())};document.addEventListener("touchstart",e),document.addEventListener("touchend",i),this._touchHandlers={handleTouchStart:e,handleTouchEnd:i}}removeTouchHandlers(){let e=this._touchHandlers;e&&(document.removeEventListener("touchstart",e.handleTouchStart),document.removeEventListener("touchend",e.handleTouchEnd))}handlePathClick(){this.editingPath=!0,this.pathInputValue=this.currentFullPath||this.currentPath||"",this.requestUpdate(),setTimeout(()=>{this.pathInputRef.value&&(this.pathInputRef.value.focus(),this.pathInputRef.value.select())},0)}handlePathInput(e){let i=e.target;this.pathInputValue=i.value}handlePathKeyDown(e){e.key==="Enter"?(e.preventDefault(),this.navigateToPath()):e.key==="Escape"&&(e.preventDefault(),this.cancelPathEdit())}handlePathBlur(){}async navigateToPath(){let e=this.pathInputValue.trim();e?(this.editingPath=!1,await this.loadDirectory(e)):this.cancelPathEdit()}cancelPathEdit(){this.editingPath=!1,this.pathInputValue=""}};_([$({type:Boolean})],te.prototype,"visible",2),_([$({type:String})],te.prototype,"mode",2),_([$({type:Object})],te.prototype,"session",2),_([A()],te.prototype,"currentPath",2),_([A()],te.prototype,"currentFullPath",2),_([A()],te.prototype,"files",2),_([A()],te.prototype,"loading",2),_([A()],te.prototype,"selectedFile",2),_([A()],te.prototype,"preview",2),_([A()],te.prototype,"diff",2),_([A()],te.prototype,"diffContent",2),_([A()],te.prototype,"gitFilter",2),_([A()],te.prototype,"showHidden",2),_([A()],te.prototype,"gitStatus",2),_([A()],te.prototype,"previewLoading",2),_([A()],te.prototype,"showDiff",2),_([A()],te.prototype,"errorMessage",2),_([A()],te.prototype,"mobileView",2),_([A()],te.prototype,"isMobile",2),_([A()],te.prototype,"editingPath",2),_([A()],te.prototype,"pathInputValue",2),te=_([z("file-browser")],te);Z();var Dt=N("session-create-form"),ge=class extends F{constructor(){super(...arguments);this.workingDir="~/";this.command="zsh";this.sessionName="";this.disabled=!1;this.visible=!1;this.spawnWindow=!1;this.titleMode="dynamic";this.isCreating=!1;this.showFileBrowser=!1;this.selectedQuickStart="zsh";this.quickStartCommands=[{label:"claude",command:"claude"},{label:"gemini",command:"gemini"},{label:"zsh",command:"zsh"},{label:"python3",command:"python3"},{label:"node",command:"node"},{label:"pnpm run dev",command:"pnpm run dev"}];this.STORAGE_KEY_WORKING_DIR="vibetunnel_last_working_dir";this.STORAGE_KEY_COMMAND="vibetunnel_last_command";this.STORAGE_KEY_SPAWN_WINDOW="vibetunnel_spawn_window";this.STORAGE_KEY_TITLE_MODE="vibetunnel_title_mode";this.handleGlobalKeyDown=e=>{if(this.visible){if(e.key==="Escape")e.preventDefault(),e.stopPropagation(),this.handleCancel();else if(e.key==="Enter"){if(e.target instanceof HTMLTextAreaElement)return;!this.disabled&&!this.isCreating&&this.workingDir?.trim()&&this.command?.trim()&&(e.preventDefault(),e.stopPropagation(),this.handleCreate())}}}}createRenderRoot(){return this}connectedCallback(){super.connectedCallback(),this.loadFromLocalStorage()}disconnectedCallback(){super.disconnectedCallback(),this.visible&&document.removeEventListener("keydown",this.handleGlobalKeyDown)}loadFromLocalStorage(){try{let e=localStorage.getItem(this.STORAGE_KEY_WORKING_DIR),i=localStorage.getItem(this.STORAGE_KEY_COMMAND),s=localStorage.getItem(this.STORAGE_KEY_SPAWN_WINDOW),o=localStorage.getItem(this.STORAGE_KEY_TITLE_MODE);Dt.debug(`loading from localStorage: workingDir=${e}, command=${i}, spawnWindow=${s}, titleMode=${o}`),e&&(this.workingDir=e),i&&(this.command=i),s!==null&&(this.spawnWindow=s==="true"),o!==null?Object.values(Ei).includes(o)?this.titleMode=o:this.titleMode="dynamic":this.titleMode="dynamic",this.requestUpdate()}catch{Dt.warn("failed to load from localStorage")}}saveToLocalStorage(){try{let e=this.workingDir?.trim()||"",i=this.command?.trim()||"";Dt.debug(`saving to localStorage: workingDir=${e}, command=${i}, spawnWindow=${this.spawnWindow}, titleMode=${this.titleMode}`),e&&localStorage.setItem(this.STORAGE_KEY_WORKING_DIR,e),i&&localStorage.setItem(this.STORAGE_KEY_COMMAND,i),localStorage.setItem(this.STORAGE_KEY_SPAWN_WINDOW,String(this.spawnWindow)),localStorage.setItem(this.STORAGE_KEY_TITLE_MODE,this.titleMode)}catch{Dt.warn("failed to save to localStorage")}}updated(e){super.updated(e),e.has("visible")&&(this.visible?(this.loadFromLocalStorage(),document.addEventListener("keydown",this.handleGlobalKeyDown)):document.removeEventListener("keydown",this.handleGlobalKeyDown))}handleWorkingDirChange(e){let i=e.target;this.workingDir=i.value,this.dispatchEvent(new CustomEvent("working-dir-change",{detail:this.workingDir}))}handleCommandChange(e){let i=e.target;this.command=i.value,this.command.toLowerCase().includes("claude")&&(this.titleMode="dynamic")}handleSessionNameChange(e){let i=e.target;this.sessionName=i.value}handleSpawnWindowChange(){this.spawnWindow=!this.spawnWindow}handleTitleModeChange(e){let i=e.target;this.titleMode=i.value}getTitleModeDescription(){switch(this.titleMode){case"none":return"Apps control their own titles";case"filter":return"Blocks all title changes";case"static":return"Shows path and command";case"dynamic":return"\u25CB idle \u25CF active \u25B6 running";default:return""}}handleBrowse(){this.showFileBrowser=!0}handleDirectorySelected(e){this.workingDir=e.detail,this.showFileBrowser=!1}handleBrowserCancel(){this.showFileBrowser=!1}async handleCreate(){if(!this.workingDir?.trim()||!this.command?.trim()){this.dispatchEvent(new CustomEvent("error",{detail:"Please fill in both working directory and command"}));return}this.isCreating=!0;let e={command:this.parseCommand(this.command?.trim()||""),workingDir:this.workingDir?.trim()||"",spawn_terminal:this.spawnWindow,titleMode:this.titleMode};this.spawnWindow||(e.cols=120,e.rows=30),this.sessionName?.trim()&&(e.name=this.sessionName.trim());try{let i=await fetch("/api/sessions",{method:"POST",headers:{"Content-Type":"application/json",...this.authClient.getAuthHeader()},body:JSON.stringify(e)});if(i.ok){let s=await i.json();this.saveToLocalStorage(),this.command="",this.sessionName="",this.dispatchEvent(new CustomEvent("session-created",{detail:s}))}else{let s=await i.json(),o=s.details||s.error||"Unknown error";this.dispatchEvent(new CustomEvent("error",{detail:o}))}}catch(i){Dt.error("error creating session:",i),this.dispatchEvent(new CustomEvent("error",{detail:"Failed to create session"}))}finally{this.isCreating=!1}}parseCommand(e){let i=[],s="",o=!1,c="";for(let r=0;r<e.length;r++){let a=e[r];(a==='"'||a==="'")&&!o?(o=!0,c=a):a===c&&o?(o=!1,c=""):a===" "&&!o?s&&(i.push(s),s=""):s+=a}return s&&i.push(s),i}handleCancel(){this.dispatchEvent(new CustomEvent("cancel"))}handleQuickStart(e){this.command=e,this.selectedQuickStart=e,e.toLowerCase().includes("claude")&&(this.titleMode="dynamic")}render(){return this.visible?S`
      <div class="modal-backdrop flex items-center justify-center">
        <div
          class="modal-content font-mono text-sm w-full max-w-[calc(100vw-1rem)] sm:max-w-md lg:max-w-[576px] mx-2 sm:mx-4"
          style="view-transition-name: create-session-modal"
        >
          <div class="p-4 pb-4 mb-3 border-b border-dark-border relative">
            <h2 class="text-accent-green text-lg font-bold">New Session</h2>
            <button
              class="absolute top-4 right-4 text-dark-text-muted hover:text-dark-text transition-colors p-1"
              @click=${this.handleCancel}
              title="Close"
              aria-label="Close modal"
            >
              <svg
                class="w-6 h-6"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </button>
          </div>

          <div class="p-3 sm:p-3 lg:p-4">
            <!-- Session Name -->
            <div class="mb-4">
              <label class="form-label">Session Name (Optional):</label>
              <input
                type="text"
                class="input-field"
                .value=${this.sessionName}
                @input=${this.handleSessionNameChange}
                placeholder="My Session"
                ?disabled=${this.disabled||this.isCreating}
              />
            </div>

            <!-- Command -->
            <div class="mb-4">
              <label class="form-label">Command:</label>
              <input
                type="text"
                class="input-field"
                .value=${this.command}
                @input=${this.handleCommandChange}
                placeholder="zsh"
                ?disabled=${this.disabled||this.isCreating}
              />
            </div>

            <!-- Working Directory -->
            <div class="mb-4">
              <label class="form-label">Working Directory:</label>
              <div class="flex gap-4">
                <input
                  type="text"
                  class="input-field"
                  .value=${this.workingDir}
                  @input=${this.handleWorkingDirChange}
                  placeholder="~/"
                  ?disabled=${this.disabled||this.isCreating}
                />
                <button
                  class="btn-secondary font-mono px-4"
                  @click=${this.handleBrowse}
                  ?disabled=${this.disabled||this.isCreating}
                >
                  📁
                </button>
              </div>
            </div>

            <!-- Spawn Window Toggle -->
            <div class="mb-4 flex items-center justify-between">
              <div class="flex-1 pr-4">
                <span class="text-dark-text text-sm">Spawn window</span>
                <p class="text-xs text-dark-text-muted mt-1">Opens native terminal window</p>
              </div>
              <button
                role="switch"
                aria-checked="${this.spawnWindow}"
                @click=${this.handleSpawnWindowChange}
                class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-dark-bg ${this.spawnWindow?"bg-accent-green":"bg-dark-border"}"
                ?disabled=${this.disabled||this.isCreating}
              >
                <span
                  class="inline-block h-5 w-5 transform rounded-full bg-white transition-transform ${this.spawnWindow?"translate-x-5":"translate-x-0.5"}"
                ></span>
              </button>
            </div>

            <!-- Terminal Title Mode -->
            <div class="mb-4 flex items-center justify-between">
              <div class="flex-1 pr-4">
                <span class="text-dark-text text-sm">Terminal Title Mode</span>
                <p class="text-xs text-dark-text-muted mt-1 opacity-50">
                  ${this.getTitleModeDescription()}
                </p>
              </div>
              <div class="relative">
                <select
                  .value=${this.titleMode}
                  @change=${this.handleTitleModeChange}
                  class="bg-[#1a1a1a] border border-dark-border rounded-lg px-3 py-2 pr-8 text-dark-text text-sm transition-all duration-200 hover:border-accent-green-darker focus:border-accent-green focus:outline-none appearance-none cursor-pointer"
                  style="min-width: 140px"
                  ?disabled=${this.disabled||this.isCreating}
                >
                  <option value="${"none"}" class="bg-[#1a1a1a] text-dark-text" ?selected=${this.titleMode==="none"}>None</option>
                  <option value="${"filter"}" class="bg-[#1a1a1a] text-dark-text" ?selected=${this.titleMode==="filter"}>Filter</option>
                  <option value="${"static"}" class="bg-[#1a1a1a] text-dark-text" ?selected=${this.titleMode==="static"}>Static</option>
                  <option value="${"dynamic"}" class="bg-[#1a1a1a] text-dark-text" ?selected=${this.titleMode==="dynamic"}>Dynamic</option>
                </select>
                <div class="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-dark-text-muted">
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>
            </div>

            <!-- Quick Start Section -->
            <div class="mb-4">
              <label class="form-label text-dark-text-muted uppercase text-xs tracking-wider"
                >Quick Start</label
              >
              <div class="grid grid-cols-2 gap-3 mt-2">
                ${this.quickStartCommands.map(({label:e,command:i})=>S`
                    <button
                      @click=${()=>this.handleQuickStart(i)}
                      class="${this.command===i?"px-4 py-3 rounded border text-left transition-all bg-accent-green bg-opacity-20 border-accent-green text-accent-green":"px-4 py-3 rounded border text-left transition-all bg-dark-border bg-opacity-10 border-dark-border text-dark-text hover:bg-opacity-20 hover:border-dark-text-secondary"}"
                      ?disabled=${this.disabled||this.isCreating}
                    >
                      ${e==="gemini"?"\u2728 ":""}${e==="claude"?"\u2728 ":""}${e==="pnpm run dev"?"\u25B6\uFE0F ":""}${e}
                    </button>
                  `)}
              </div>
            </div>

            <div class="flex gap-4 mt-4">
              <button
                class="btn-ghost font-mono flex-1 py-3"
                @click=${this.handleCancel}
                ?disabled=${this.isCreating}
              >
                Cancel
              </button>
              <button
                class="btn-primary font-mono flex-1 py-3 disabled:opacity-50 disabled:cursor-not-allowed"
                @click=${this.handleCreate}
                ?disabled=${this.disabled||this.isCreating||!this.workingDir?.trim()||!this.command?.trim()}
              >
                ${this.isCreating?"Creating...":"Create"}
              </button>
            </div>
          </div>
        </div>
      </div>

      <file-browser
        .visible=${this.showFileBrowser}
        .mode=${"select"}
        .session=${{workingDir:this.workingDir}}
        @directory-selected=${this.handleDirectorySelected}
        @browser-cancel=${this.handleBrowserCancel}
      ></file-browser>
    `:S``}};_([$({type:String})],ge.prototype,"workingDir",2),_([$({type:String})],ge.prototype,"command",2),_([$({type:String})],ge.prototype,"sessionName",2),_([$({type:Boolean})],ge.prototype,"disabled",2),_([$({type:Boolean})],ge.prototype,"visible",2),_([$({type:Object})],ge.prototype,"authClient",2),_([$({type:Boolean})],ge.prototype,"spawnWindow",2),_([$({type:String})],ge.prototype,"titleMode",2),_([A()],ge.prototype,"isCreating",2),_([A()],ge.prototype,"showFileBrowser",2),_([A()],ge.prototype,"selectedQuickStart",2),ge=_([z("session-create-form")],ge);var Rs=(h,t,e)=>{let i=new Map;for(let s=t;s<=e;s++)i.set(h[s],s);return i},Hs=st(class extends We{constructor(h){if(super(h),h.type!==si.CHILD)throw Error("repeat() can only be used in text expressions")}dt(h,t,e){let i;e===void 0?e=t:t!==void 0&&(i=t);let s=[],o=[],c=0;for(let r of h)s[c]=i?i(r,c):c,o[c]=e(r,c),c++;return{values:o,keys:s}}render(h,t,e){return this.dt(h,t,e).values}update(h,[t,e,i]){let s=Es(h),{values:o,keys:c}=this.dt(t,e,i);if(!Array.isArray(s))return this.ut=c,o;let r=this.ut??(this.ut=[]),a=[],g,m,l=0,v=s.length-1,f=0,b=o.length-1;for(;l<=v&&f<=b;)if(s[l]===null)l++;else if(s[v]===null)v--;else if(r[l]===c[f])a[f]=qe(s[l],o[f]),l++,f++;else if(r[v]===c[b])a[b]=qe(s[v],o[b]),v--,b--;else if(r[l]===c[b])a[b]=qe(s[l],o[b]),pt(h,a[b+1],s[l]),l++,b--;else if(r[v]===c[f])a[f]=qe(s[v],o[f]),pt(h,s[l],s[v]),v--,f++;else if(g===void 0&&(g=Rs(c,f,b),m=Rs(r,l,v)),g.has(r[l]))if(g.has(r[v])){let w=m.get(c[f]),n=w!==void 0?s[w]:null;if(n===null){let d=pt(h,s[l]);qe(d,o[f]),a[f]=d}else a[f]=qe(n,o[f]),pt(h,s[l],n),s[w]=null;f++}else ni(s[v]),v--;else ni(s[l]),l++;for(;f<=b;){let w=pt(h,a[b+1]);qe(w,o[f]),a[f++]=w}for(;l<=v;){let w=s[l++];w!==null&&ni(w)}return this.ut=c,ri(h,a),Fe}});Z();function zr(h){let t=[];if(h.fg!==void 0)if(h.fg>=0&&h.fg<=255)t.push(`fg="${h.fg}"`);else{let e=h.fg>>16&255,i=h.fg>>8&255,s=h.fg&255;t.push(`fg="${e},${i},${s}"`)}if(h.bg!==void 0)if(h.bg>=0&&h.bg<=255)t.push(`bg="${h.bg}"`);else{let e=h.bg>>16&255,i=h.bg>>8&255,s=h.bg&255;t.push(`bg="${e},${i},${s}"`)}return h.attributes&&(h.attributes&1&&t.push("bold"),h.attributes&2&&t.push("dim"),h.attributes&4&&t.push("italic"),h.attributes&8&&t.push("underline"),h.attributes&16&&t.push("inverse"),h.attributes&32&&t.push("invisible"),h.attributes&64&&t.push("strikethrough")),t.join(" ")}function Bs(h,t=!0){let e=[];for(let i of h){let s="";if(t){let o="",c="",r=()=>{c&&(o?s+=`[style ${o}]${c}[/style]`:s+=c,c="")};for(let a of i){let g=zr(a);g!==o&&(r(),o=g),c+=a.char}r()}else for(let o of i)s+=o.char;e.push(s.trimEnd())}return e.join(`
`)}Z();Pe();var ce=N("buffer-subscription-service"),qr=191,Vi=class{constructor(){this.ws=null;this.subscriptions=new Map;this.reconnectAttempts=0;this.reconnectTimer=null;this.pingInterval=null;this.isConnecting=!1;this.messageQueue=[];this.initialized=!1;this.noAuthMode=null}async initialize(){this.initialized||(this.initialized=!0,await this.checkNoAuthMode(),setTimeout(()=>{this.connect()},100))}async checkNoAuthMode(){try{let t=await fetch("/api/auth/config");if(t.ok){let e=await t.json();this.noAuthMode=e.noAuth===!0}}catch(t){ce.warn("Failed to check auth config:",t),this.noAuthMode=!1}}isNoAuthMode(){return this.noAuthMode===!0}connect(){if(this.isConnecting||this.ws&&this.ws.readyState===WebSocket.OPEN)return;let e=j.getCurrentUser()?.token;if(!e&&!this.isNoAuthMode()){ce.warn("No auth token available, postponing WebSocket connection"),setTimeout(()=>{this.initialized&&!this.ws&&this.connect()},1e3);return}this.isConnecting=!0;let s=`${window.location.protocol==="https:"?"wss:":"ws:"}//${window.location.host}/buffers`;e&&(s+=`?token=${encodeURIComponent(e)}`),ce.log(`connecting to ${s}`);try{this.ws=new WebSocket(s),this.ws.binaryType="arraybuffer",this.ws.onopen=()=>{for(ce.log("connected"),this.isConnecting=!1,this.reconnectAttempts=0,this.startPingPong();this.messageQueue.length>0;){let o=this.messageQueue.shift();o&&this.sendMessage(o)}this.subscriptions.forEach((o,c)=>{this.sendMessage({type:"subscribe",sessionId:c})})},this.ws.onmessage=o=>{this.handleMessage(o.data)},this.ws.onerror=o=>{ce.error("websocket error",o)},this.ws.onclose=()=>{ce.log("disconnected"),this.isConnecting=!1,this.ws=null,this.stopPingPong(),this.scheduleReconnect()}}catch(o){ce.error("failed to create websocket",o),this.isConnecting=!1,this.scheduleReconnect()}}scheduleReconnect(){if(this.reconnectTimer)return;let t=Math.min(1e3*2**this.reconnectAttempts,3e4);this.reconnectAttempts++,ce.log(`reconnecting in ${t}ms (attempt ${this.reconnectAttempts})`),this.reconnectTimer=window.setTimeout(()=>{this.reconnectTimer=null,this.connect()},t)}startPingPong(){this.stopPingPong(),this.pingInterval=window.setInterval(()=>{},1e4)}stopPingPong(){this.pingInterval&&(clearInterval(this.pingInterval),this.pingInterval=null)}sendMessage(t){if(!this.ws||this.ws.readyState!==WebSocket.OPEN){(t.type==="subscribe"||t.type==="unsubscribe")&&this.messageQueue.push(t);return}this.ws.send(JSON.stringify(t))}handleMessage(t){t instanceof ArrayBuffer?this.handleBinaryMessage(t):this.handleJsonMessage(t)}handleJsonMessage(t){try{let e=JSON.parse(t);switch(e.type){case"connected":ce.log(`connected to server, version: ${e.version}`);break;case"subscribed":ce.debug(`subscribed to session: ${e.sessionId}`);break;case"ping":this.sendMessage({type:"pong"});break;case"error":ce.error(`server error: ${e.message}`);break;default:ce.warn(`unknown message type: ${e.type}`)}}catch(e){ce.error("failed to parse JSON message",e)}}handleBinaryMessage(t){try{let e=new DataView(t),i=0,s=e.getUint8(i);if(i+=1,s!==qr){ce.error(`invalid magic byte: ${s}`);return}let o=e.getUint32(i,!0);i+=4;let c=new Uint8Array(t,i,o),r=new TextDecoder().decode(c);i+=o;let a=t.slice(i);Promise.resolve().then(()=>(qi(),zs)).then(({TerminalRenderer:g})=>{try{let m=g.decodeBinaryBuffer(a),l=this.subscriptions.get(r);l&&l.forEach(v=>{try{v(m)}catch(f){ce.error("error in update handler",f)}})}catch(m){ce.error("failed to decode binary buffer",m)}}).catch(g=>{ce.error("failed to import terminal renderer",g)})}catch(e){ce.error("failed to parse binary message",e)}}subscribe(t,e){this.initialized||this.initialize(),this.subscriptions.has(t)||(this.subscriptions.set(t,new Set),this.sendMessage({type:"subscribe",sessionId:t}));let i=this.subscriptions.get(t);return i&&i.add(e),()=>{let s=this.subscriptions.get(t);s&&(s.delete(e),s.size===0&&(this.subscriptions.delete(t),this.sendMessage({type:"unsubscribe",sessionId:t})))}}dispose(){this.reconnectTimer&&(clearTimeout(this.reconnectTimer),this.reconnectTimer=null),this.stopPingPong(),this.ws&&(this.ws.close(),this.ws=null),this.subscriptions.clear(),this.messageQueue=[]}},pi=new Vi;qi();var ze=class extends F{constructor(){super(...arguments);this.sessionId="";this.buffer=null;this.error=null;this.displayedFontSize=14;this.visibleRows=0;this.container=null;this.resizeObserver=null;this.unsubscribe=null;this.lastTextSnapshot=null}createRenderRoot(){return this}disconnectedCallback(){this.unsubscribeFromBuffer(),this.resizeObserver&&(this.resizeObserver.disconnect(),this.resizeObserver=null),super.disconnectedCallback()}firstUpdated(){this.container=this.querySelector("#buffer-container"),this.container&&(this.setupResize(),this.sessionId&&this.subscribeToBuffer())}updated(e){super.updated(e),e.has("sessionId")&&(this.buffer=null,this.error=null,this.unsubscribeFromBuffer(),this.sessionId&&this.subscribeToBuffer()),this.container&&this.buffer&&this.updateBufferContent()}setupResize(){this.container&&(this.resizeObserver=new ResizeObserver(()=>{this.calculateDimensions()}),this.resizeObserver.observe(this.container))}calculateDimensions(){if(!this.container)return;let e=this.container.clientWidth,i=this.container.clientHeight,s=this.buffer?.cols||80,o=document.createElement("div");o.className="terminal-line",o.style.position="absolute",o.style.visibility="hidden",o.style.fontSize="14px",o.textContent="0".repeat(s),document.body.appendChild(o);let c=o.getBoundingClientRect().width;document.body.removeChild(o);let r=e/c*14;this.displayedFontSize=Math.min(32,r);let a=this.displayedFontSize*1.2;this.visibleRows=Math.floor(i/a),this.buffer&&this.requestUpdate()}subscribeToBuffer(){this.sessionId&&(this.unsubscribe=pi.subscribe(this.sessionId,e=>{this.buffer=e,this.error=null,this.checkForContentChange(),this.calculateDimensions(),this.requestUpdate()}))}checkForContentChange(){if(!this.buffer)return;let e=this.getTextWithStyles(!0);if(this.lastTextSnapshot===null){this.lastTextSnapshot=e;return}e!==this.lastTextSnapshot&&(this.lastTextSnapshot=e,this.dispatchEvent(new CustomEvent("content-changed",{bubbles:!0,composed:!0})))}unsubscribeFromBuffer(){this.unsubscribe&&(this.unsubscribe(),this.unsubscribe=null)}connectedCallback(){super.connectedCallback()}render(){let e=this.displayedFontSize*1.2;return S`
      <style>
        /* Dynamic terminal sizing for this instance */
        vibe-terminal-buffer .terminal-container {
          font-size: ${this.displayedFontSize}px;
          line-height: ${e}px;
        }

        vibe-terminal-buffer .terminal-line {
          height: ${e}px;
          line-height: ${e}px;
        }
      </style>
      <div
        class="relative w-full h-full overflow-hidden bg-black"
        style="view-transition-name: terminal-${this.sessionId}; min-height: 200px;"
      >
        ${this.error?S`
              <div class="absolute inset-0 flex items-center justify-center">
                <div class="text-red-500 text-sm">${this.error}</div>
              </div>
            `:S`
              <div
                id="buffer-container"
                class="terminal-container w-full h-full overflow-x-auto overflow-y-hidden font-mono antialiased"
              ></div>
            `}
      </div>
    `}updateBufferContent(){if(!this.container||!this.buffer||this.visibleRows===0)return;let e=this.displayedFontSize*1.2,i="",s=0;this.buffer.cells.length>this.visibleRows&&(s=this.buffer.cells.length-this.visibleRows);for(let o=s;o<this.buffer.cells.length;o++){let c=this.buffer.cells[o],a=o===this.buffer.cursorY?this.buffer.cursorX:-1,g=Wi.renderLineFromCells(c,a);i+=`<div class="terminal-line" style="height: ${e}px; line-height: ${e}px;">${g}</div>`}if(i===""||this.buffer.cells.length===0)for(let o=0;o<Math.max(3,this.visibleRows);o++)i+=`<div class="terminal-line" style="height: ${e}px; line-height: ${e}px;">&nbsp;</div>`;this.container.innerHTML=i}refresh(){this.buffer&&this.requestUpdate()}getTextWithStyles(e=!0){return this.buffer?Bs(this.buffer.cells,e):""}};_([$({type:String})],ze.prototype,"sessionId",2),_([A()],ze.prototype,"buffer",2),_([A()],ze.prototype,"error",2),_([A()],ze.prototype,"displayedFontSize",2),_([A()],ze.prototype,"visibleRows",2),ze=_([z("vibe-terminal-buffer")],ze);var bt=class extends F{constructor(){super(...arguments);this.size=16}render(){return S`
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        style="--icon-size: ${this.size}px"
        class="copy-icon"
      >
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
      </svg>
    `}};bt.styles=Et`
    :host {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      opacity: 0.4;
      transition: opacity 0.2s ease;
    }

    :host(:hover) {
      opacity: 0.8;
    }

    svg {
      display: block;
      width: var(--icon-size, 16px);
      height: var(--icon-size, 16px);
    }
  `,_([$({type:Number})],bt.prototype,"size",2),bt=_([z("copy-icon")],bt);Z();var Ks=N("clickable-path"),ot=class extends F{constructor(){super(...arguments);this.path="";this.class="";this.iconSize=12}createRenderRoot(){return this}async handleClick(e){if(e.stopPropagation(),e.preventDefault(),!!this.path)try{if(await mt(this.path))Ks.log("Path copied to clipboard",{path:this.path}),this.dispatchEvent(new CustomEvent("path-copied",{detail:{path:this.path},bubbles:!0,composed:!0}));else throw new Error("Copy command failed")}catch(i){Ks.error("Failed to copy path to clipboard",{error:i,path:this.path}),this.dispatchEvent(new CustomEvent("path-copy-failed",{detail:{path:this.path,error:i instanceof Error?i.message:"Unknown error"},bubbles:!0,composed:!0}))}}render(){if(!this.path)return S``;let e=nt(this.path);return S`
      <div
        class="truncate cursor-pointer hover:text-accent-green transition-colors inline-flex items-center gap-1 max-w-full ${this.class}"
        title="Click to copy path"
        @click=${this.handleClick}
      >
        <span class="truncate">${e}</span>
        <copy-icon size="${this.iconSize}" class="flex-shrink-0"></copy-icon>
      </div>
    `}};_([$({type:String})],ot.prototype,"path",2),_([$({type:String})],ot.prototype,"class",2),_([$({type:Number})],ot.prototype,"iconSize",2),ot=_([z("clickable-path")],ot);var yt=N("session-card"),Ke=class extends F{constructor(){super(...arguments);this.killing=!1;this.killingFrame=0;this.isActive=!1;this.killingInterval=null;this.activityTimeout=null}createRenderRoot(){return this}connectedCallback(){super.connectedCallback()}disconnectedCallback(){super.disconnectedCallback(),this.killingInterval&&clearInterval(this.killingInterval),this.activityTimeout&&clearTimeout(this.activityTimeout)}handleCardClick(){this.dispatchEvent(new CustomEvent("session-select",{detail:this.session,bubbles:!0,composed:!0}))}handleContentChanged(){this.session.status==="running"&&(this.isActive=!0,this.activityTimeout&&clearTimeout(this.activityTimeout),this.activityTimeout=window.setTimeout(()=>{this.isActive=!1,this.activityTimeout=null},500))}async handleKillClick(e){e.stopPropagation(),e.preventDefault(),await this.kill()}async kill(){if(this.killing||this.session.status!=="running"&&this.session.status!=="exited")return!1;let e=this.session.status==="exited";this.killing=!0,this.killingFrame=0,this.killingInterval=window.setInterval(()=>{this.killingFrame=(this.killingFrame+1)%4,this.requestUpdate()},200),e&&(this.classList.add("black-hole-collapsing"),await new Promise(i=>setTimeout(i,300)));try{let i=this.session.status==="exited"?`/api/sessions/${this.session.id}/cleanup`:`/api/sessions/${this.session.id}`,s=this.session.status==="exited"?"cleanup":"kill",o=await fetch(i,{method:"DELETE",headers:{...this.authClient.getAuthHeader()}});if(!o.ok){let c=await o.text();throw yt.error(`Failed to ${s} session`,{errorData:c,sessionId:this.session.id}),new Error(`${s} failed: ${o.status}`)}return this.dispatchEvent(new CustomEvent("session-killed",{detail:{sessionId:this.session.id,session:this.session},bubbles:!0,composed:!0})),yt.log(`Session ${this.session.id} ${s==="cleanup"?"cleaned up":"killed"} successfully`),!0}catch(i){return yt.error("Error killing session",{error:i,sessionId:this.session.id}),this.dispatchEvent(new CustomEvent("session-kill-error",{detail:{sessionId:this.session.id,error:i instanceof Error?i.message:"Unknown error"},bubbles:!0,composed:!0})),!1}finally{this.stopKillingAnimation()}}stopKillingAnimation(){this.killing=!1,this.killingInterval&&(clearInterval(this.killingInterval),this.killingInterval=null)}getKillingText(){let e=["\u280B","\u2819","\u2839","\u2838","\u283C","\u2834","\u2826","\u2827","\u2807","\u280F"];return e[this.killingFrame%e.length]}async handlePidClick(e){e.stopPropagation(),e.preventDefault(),this.session.pid&&(await mt(this.session.pid.toString())?yt.log("PID copied to clipboard",{pid:this.session.pid}):yt.error("Failed to copy PID to clipboard",{pid:this.session.pid}))}render(){return this.session.name||yt.warn("Session missing name",{sessionId:this.session.id,name:this.session.name,command:this.session.command}),S`
      <div
        class="card cursor-pointer overflow-hidden flex flex-col h-full ${this.killing?"opacity-60":""} ${this.isActive&&this.session.status==="running"?"shadow-[0_0_0_2px_#00ff88] shadow-glow-green-sm":""}"
        style="view-transition-name: session-${this.session.id}; --session-id: session-${this.session.id}"
        data-session-id="${this.session.id}"
        data-testid="session-card"
        data-session-status="${this.session.status}"
        data-is-killing="${this.killing}"
        @click=${this.handleCardClick}
      >
        <!-- Compact Header -->
        <div
          class="flex justify-between items-center px-3 py-2 border-b border-dark-border bg-dark-bg-secondary"
        >
          <div class="text-xs font-mono pr-2 flex-1 min-w-0 text-accent-green">
            <div class="truncate" title="${this.session.name||this.session.command.join(" ")}">
              ${this.session.name||this.session.command.join(" ")}
            </div>
          </div>
          ${this.session.status==="running"||this.session.status==="exited"?S`
                <button
                  class="btn-ghost ${this.session.status==="running"?"text-status-error":"text-status-warning"} disabled:opacity-50 flex-shrink-0 p-1 rounded-full hover:bg-opacity-20 transition-all ${this.session.status==="running"?"hover:bg-status-error":"hover:bg-status-warning"}"
                  @click=${this.handleKillClick}
                  ?disabled=${this.killing}
                  title="${this.session.status==="running"?"Kill session":"Clean up session"}"
                  data-testid="kill-session-button"
                >
                  ${this.killing?S`<span class="block w-5 h-5 flex items-center justify-center"
                        >${this.getKillingText()}</span
                      >`:S`
                        <svg
                          class="w-5 h-5"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                          xmlns="http://www.w3.org/2000/svg"
                        >
                          <circle cx="12" cy="12" r="10" stroke-width="2" />
                          <path
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            stroke-width="2"
                            d="M15 9l-6 6m0-6l6 6"
                          />
                        </svg>
                      `}
                </button>
              `:""}
        </div>

        <!-- Terminal display (main content) -->
        <div
          class="session-preview bg-black overflow-hidden flex-1 ${this.session.status==="exited"?"session-exited":""}"
        >
          ${this.killing?S`
                <div class="w-full h-full flex items-center justify-center text-status-error">
                  <div class="text-center font-mono">
                    <div class="text-4xl mb-2">${this.getKillingText()}</div>
                    <div class="text-sm">Killing session...</div>
                  </div>
                </div>
              `:S`
                <vibe-terminal-buffer
                  .sessionId=${this.session.id}
                  class="w-full h-full"
                  style="pointer-events: none;"
                  @content-changed=${this.handleContentChanged}
                ></vibe-terminal-buffer>
              `}
        </div>

        <!-- Compact Footer -->
        <div
          class="px-3 py-2 text-dark-text-muted text-xs border-t border-dark-border bg-dark-bg-secondary"
        >
          <div class="flex justify-between items-center min-w-0">
            <span 
              class="${this.getStatusColor()} text-xs flex items-center gap-1 flex-shrink-0"
              data-status="${this.session.status}"
              data-killing="${this.killing}"
            >
              <div class="w-2 h-2 rounded-full ${this.getStatusDotColor()}"></div>
              ${this.getStatusText()}
              ${this.session.status==="running"&&this.isActive?S`<span class="text-accent-green animate-pulse ml-1">●</span>`:""}
            </span>
            ${this.session.pid?S`
                  <span
                    class="cursor-pointer hover:text-accent-green transition-colors text-xs flex-shrink-0 ml-2 inline-flex items-center gap-1"
                    @click=${this.handlePidClick}
                    title="Click to copy PID"
                  >
                    PID: ${this.session.pid} <copy-icon size="14"></copy-icon>
                  </span>
                `:""}
          </div>
          <div class="text-xs opacity-75 min-w-0 mt-1">
            <clickable-path .path=${this.session.workingDir} .iconSize=${12}></clickable-path>
          </div>
        </div>
      </div>
    `}getStatusText(){return this.session.active===!1?"waiting":this.session.status}getStatusColor(){return this.session.active===!1?"text-dark-text-muted":this.session.status==="running"?"text-status-success":"text-status-warning"}getStatusDotColor(){return this.session.active===!1?"bg-dark-text-muted":this.session.status==="running"?"bg-status-success":"bg-status-warning"}};_([$({type:Object})],Ke.prototype,"session",2),_([$({type:Object})],Ke.prototype,"authClient",2),_([A()],Ke.prototype,"killing",2),_([A()],Ke.prototype,"killingFrame",2),_([A()],Ke.prototype,"isActive",2),Ke=_([z("session-card")],Ke);Z();var Ot=N("session-list"),Me=class extends F{constructor(){super(...arguments);this.sessions=[];this.loading=!1;this.hideExited=!0;this.selectedSessionId=null;this.compactMode=!1;this.cleaningExited=!1;this.previousRunningCount=0}createRenderRoot(){return this}handleRefresh(){this.dispatchEvent(new CustomEvent("refresh"))}handleSessionSelect(e){let i=e.detail;this.dispatchEvent(new CustomEvent("navigate-to-session",{detail:{sessionId:i.id},bubbles:!0,composed:!0}))}async handleSessionKilled(e){let{sessionId:i}=e.detail;Ot.debug(`session ${i} killed, updating session list`),this.sessions=this.sessions.filter(s=>s.id!==i),this.dispatchEvent(new CustomEvent("refresh"))}handleSessionKillError(e){let{sessionId:i,error:s}=e.detail;Ot.error(`failed to kill session ${i}:`,s),this.dispatchEvent(new CustomEvent("error",{detail:`Failed to kill session: ${s}`}))}async handleCleanupExited(){if(!this.cleaningExited){this.cleaningExited=!0,this.requestUpdate();try{if((await fetch("/api/cleanup-exited",{method:"POST",headers:{...this.authClient.getAuthHeader()}})).ok){if(this.sessions.filter(s=>s.status==="exited").length>0){let s=this.querySelectorAll("session-card"),o=[];s.forEach(c=>{let r=c;r.session?.status==="exited"&&o.push(r)}),o.forEach(c=>{c.classList.add("black-hole-collapsing")}),o.length>0&&await new Promise(c=>setTimeout(c,300)),this.sessions=this.sessions.filter(c=>c.status!=="exited")}this.dispatchEvent(new CustomEvent("refresh"))}else this.dispatchEvent(new CustomEvent("error",{detail:"Failed to cleanup exited sessions"}))}catch(e){Ot.error("error cleaning up exited sessions:",e),this.dispatchEvent(new CustomEvent("error",{detail:"Failed to cleanup exited sessions"}))}finally{this.cleaningExited=!1,this.requestUpdate()}}}handleOpenFileBrowser(){this.dispatchEvent(new CustomEvent("open-file-browser",{bubbles:!0}))}render(){let e=this.hideExited?this.sessions.filter(i=>i.status!=="exited"):this.sessions;return S`
      <div class="font-mono text-sm p-4 bg-black" data-testid="session-list-container">
        ${e.length===0?S`
              <div class="text-dark-text-muted text-center py-8">
                ${this.loading?"Loading sessions...":this.hideExited&&this.sessions.length>0?S`
                        <div class="space-y-4 max-w-2xl mx-auto text-left">
                          <div class="text-lg font-semibold text-dark-text">
                            No running sessions
                          </div>
                          <div class="text-sm text-dark-text-muted">
                            There are exited sessions. Show them by toggling "Hide exited" above.
                          </div>
                        </div>
                      `:S`
                        <div class="space-y-6 max-w-2xl mx-auto text-left">
                          <div class="text-lg font-semibold text-dark-text">
                            No terminal sessions yet!
                          </div>

                          <div class="space-y-3">
                            <div class="text-sm text-dark-text-muted">
                              Get started by using the
                              <code class="bg-dark-bg-secondary px-2 py-1 rounded">vt</code> command
                              in your terminal:
                            </div>

                            <div
                              class="bg-dark-bg-secondary p-4 rounded-lg font-mono text-xs space-y-2"
                            >
                              <div class="text-green-400">vt pnpm run dev</div>
                              <div class="text-dark-text-muted pl-4"># Monitor your dev server</div>

                              <div class="text-green-400">vt claude --dangerously...</div>
                              <div class="text-dark-text-muted pl-4">
                                # Keep an eye on AI agents
                              </div>

                              <div class="text-green-400">vt --shell</div>
                              <div class="text-dark-text-muted pl-4">
                                # Open an interactive shell
                              </div>

                              <div class="text-green-400">vt python train.py</div>
                              <div class="text-dark-text-muted pl-4">
                                # Watch long-running scripts
                              </div>
                            </div>
                          </div>

                          <div class="space-y-3 border-t border-dark-border pt-4">
                            <div class="text-sm font-semibold text-dark-text">
                              Haven't installed the CLI yet?
                            </div>
                            <div class="text-sm text-dark-text-muted space-y-1">
                              <div>→ Click the VibeTunnel menu bar icon</div>
                              <div>→ Go to Settings → Advanced → Install CLI Tools</div>
                            </div>
                          </div>

                          <div class="text-xs text-dark-text-muted mt-4">
                            Once installed, any command prefixed with
                            <code class="bg-dark-bg-secondary px-1 rounded">vt</code> will appear
                            here, accessible from any browser at localhost:4020.
                          </div>
                        </div>
                      `}
              </div>
            `:S`
              <div class="${this.compactMode?"space-y-2":"session-flex-responsive"}">
                ${this.compactMode?S`
                      <!-- Browse Files button as special tab -->
                      <div
                        class="flex items-center gap-2 p-3 rounded-md cursor-pointer transition-all hover:bg-dark-bg-tertiary border border-dark-border bg-dark-bg-secondary"
                        @click=${this.handleOpenFileBrowser}
                        title="Browse Files (⌘O)"
                      >
                        <div class="flex-1 min-w-0">
                          <div class="text-sm font-mono text-accent-green truncate">
                            📁 Browse Files
                          </div>
                          <div class="text-xs text-dark-text-muted truncate">Open file browser</div>
                        </div>
                        <div class="flex items-center gap-2 flex-shrink-0">
                          <span class="text-dark-text-muted text-xs">⌘O</span>
                        </div>
                      </div>
                    `:""}
                ${Hs(e,i=>i.id,i=>S`
                    ${this.compactMode?S`
                          <!-- Compact list item for sidebar -->
                          <div
                            class="flex items-center gap-2 p-3 rounded-md cursor-pointer transition-all hover:bg-dark-bg-tertiary ${i.id===this.selectedSessionId?"bg-dark-bg-tertiary border border-accent-green shadow-sm":"border border-transparent"}"
                            @click=${()=>this.handleSessionSelect({detail:i})}
                          >
                            <div class="flex-1 min-w-0">
                              <div
                                class="text-sm font-mono text-accent-green truncate"
                                title="${i.name||(Array.isArray(i.command)?i.command.join(" "):i.command)}"
                              >
                                ${i.name||(Array.isArray(i.command)?i.command.join(" "):i.command)}
                              </div>
                              <div class="text-xs text-dark-text-muted truncate flex items-center gap-1">
                                ${i.status==="running"&&i.activityStatus&&Ot.debug(`Session ${i.id} activity:`,{isActive:i.activityStatus.isActive,specificStatus:i.activityStatus.specificStatus}),i.activityStatus?.specificStatus?S`
                                      <span class="text-status-warning flex-shrink-0">
                                        ${i.activityStatus.specificStatus.status}
                                      </span>
                                      <span class="text-dark-text-muted/50">·</span>
                                      <span class="truncate">
                                        ${nt(i.workingDir)}
                                      </span>
                                    `:nt(i.workingDir)}
                              </div>
                            </div>
                            <div class="flex items-center gap-2 flex-shrink-0">
                              <div
                                class="w-2 h-2 rounded-full ${i.status==="running"?i.activityStatus?.specificStatus?"bg-accent-green animate-pulse":i.activityStatus?.isActive?"bg-status-success":"bg-status-success ring-1 ring-status-success":"bg-status-warning"}"
                                title="${i.status==="running"&&i.activityStatus?i.activityStatus.specificStatus?`Active: ${i.activityStatus.specificStatus.app}`:i.activityStatus.isActive?"Active":"Idle":i.status}"
                              ></div>
                              ${i.status==="running"||i.status==="exited"?S`
                                    <button
                                      class="btn-ghost text-status-error p-1 rounded hover:bg-dark-bg"
                                      @click=${async s=>{s.stopPropagation();try{let o=i.status==="exited"?`/api/sessions/${i.id}/cleanup`:`/api/sessions/${i.id}`;(await fetch(o,{method:"DELETE",headers:this.authClient.getAuthHeader()})).ok&&this.handleSessionKilled({detail:{sessionId:i.id}})}catch(o){Ot.error("Failed to kill session",o)}}}
                                      title="${i.status==="running"?"Kill session":"Clean up session"}"
                                    >
                                      <svg
                                        class="w-4 h-4"
                                        fill="none"
                                        stroke="currentColor"
                                        viewBox="0 0 24 24"
                                      >
                                        <path
                                          stroke-linecap="round"
                                          stroke-linejoin="round"
                                          stroke-width="2"
                                          d="M6 18L18 6M6 6l12 12"
                                        />
                                      </svg>
                                    </button>
                                  `:""}
                            </div>
                          </div>
                        `:S`
                          <!-- Full session card for main view -->
                          <session-card
                            .session=${i}
                            .authClient=${this.authClient}
                            @session-select=${this.handleSessionSelect}
                            @session-killed=${this.handleSessionKilled}
                            @session-kill-error=${this.handleSessionKillError}
                          >
                          </session-card>
                        `}
                  `)}
              </div>
            `}

        ${this.renderExitedControls()}
      </div>
    `}renderExitedControls(){let e=this.sessions.filter(s=>s.status==="exited"),i=this.sessions.filter(s=>s.status==="running");return e.length===0&&i.length===0?"":S`
      <div class="flex flex-col sm:flex-row sm:flex-wrap gap-2 mt-8 pb-4 px-4 w-full">
        <!-- First group: Show/Hide Exited and Clean Exited (when visible) -->
        ${e.length>0?S`
              <div class="flex flex-col gap-2 w-full sm:w-auto">
                <!-- Show/Hide Exited button -->
                <button
                  class="font-mono text-xs sm:text-sm px-3 sm:px-6 py-2 rounded-lg border transition-all duration-200 flex-1 sm:flex-none sm:w-auto sm:min-w-[180px] ${this.hideExited?"border-dark-border bg-dark-bg-secondary text-dark-text-muted hover:bg-dark-bg-tertiary hover:text-dark-text":"border-dark-border bg-dark-bg-tertiary text-dark-text hover:bg-dark-bg-secondary"}"
                  @click=${()=>this.dispatchEvent(new CustomEvent("hide-exited-change",{detail:!this.hideExited}))}
                >
                  <div class="flex items-center justify-center gap-2 sm:gap-3">
                    <span class="hidden sm:inline"
                      >${this.hideExited?"Show":"Hide"} Exited (${e.length})</span
                    >
                    <span class="sm:hidden"
                      >${this.hideExited?"Show":"Hide"} (${e.length})</span
                    >
                    <div
                      class="w-8 h-4 rounded-full transition-colors duration-200 ${this.hideExited?"bg-dark-surface":"bg-dark-bg"}"
                    >
                      <div
                        class="w-3 h-3 rounded-full transition-transform duration-200 mt-0.5 ${this.hideExited?"translate-x-0.5 bg-dark-text-muted":"translate-x-4 bg-accent-green"}"
                      ></div>
                    </div>
                  </div>
                </button>
                
                <!-- Clean Exited button (only when Show Exited is active) -->
                ${this.hideExited?"":S`
                      <button
                        class="font-mono text-xs sm:text-sm px-3 sm:px-6 py-2 rounded-lg border transition-all duration-200 flex-1 sm:flex-none sm:w-auto sm:min-w-[120px] border-dark-border bg-dark-bg-secondary text-status-warning hover:bg-dark-bg-tertiary hover:border-status-warning"
                        @click=${this.handleCleanupExited}
                        ?disabled=${this.cleaningExited}
                      >
                        <span class="hidden sm:inline"
                          >${this.cleaningExited?"Cleaning...":`Clean Exited (${e.length})`}</span
                        >
                        <span class="sm:hidden">${this.cleaningExited?"Cleaning...":"Clean"}</span>
                      </button>
                    `}
              </div>
            `:""}
        
        <!-- Kill All button -->
        ${i.length>0?S`
              <button
                class="font-mono text-xs sm:text-sm px-3 sm:px-6 py-2 rounded-lg border transition-all duration-200 w-full sm:w-auto sm:min-w-[120px] border-status-error bg-dark-bg-secondary text-status-error hover:bg-dark-bg-tertiary hover:border-status-error"
                @click=${()=>this.dispatchEvent(new CustomEvent("kill-all-sessions"))}
              >
                Kill All (${i.length})
              </button>
            `:""}
      </div>
    `}};_([$({type:Array})],Me.prototype,"sessions",2),_([$({type:Boolean})],Me.prototype,"loading",2),_([$({type:Boolean})],Me.prototype,"hideExited",2),_([$({type:Object})],Me.prototype,"authClient",2),_([$({type:String})],Me.prototype,"selectedSessionId",2),_([$({type:Boolean})],Me.prototype,"compactMode",2),_([A()],Me.prototype,"cleaningExited",2),Me=_([z("session-list")],Me);var Xs=hr(Ws());var qs="terminal-shortcut",Vr=[{pattern:/\bctrl\+([a-z])\b/gi,keySequence:h=>`ctrl_${h[1].toLowerCase()}`},{pattern:/\bctrl\+([0-9])\b/gi,keySequence:h=>`ctrl_${h[1]}`},{pattern:/\bctrl\+f([1-9]|1[0-2])\b/gi,keySequence:h=>`ctrl_f${h[1]}`},{pattern:/\bctrl\+shift\+([a-z])\b/gi,keySequence:h=>`ctrl_shift_${h[1].toLowerCase()}`},{pattern:/\balt\+([a-z])\b/gi,keySequence:h=>`alt_${h[1].toLowerCase()}`},{pattern:/\bcmd\+([a-z])\b/gi,keySequence:h=>`cmd_${h[1].toLowerCase()}`},{pattern:/\bf([1-9]|1[0-2])\b/gi,keySequence:h=>`f${h[1]}`},{pattern:/\besc\b/gi,keySequence:()=>"escape"},{pattern:/\bescape\b/gi,keySequence:()=>"escape"},{pattern:/\btab\b/gi,keySequence:()=>"tab"},{pattern:/\bshift\+tab\b/gi,keySequence:()=>"shift_tab"},{pattern:/\benter\b/gi,keySequence:()=>"enter"},{pattern:/\breturn\b/gi,keySequence:()=>"enter"},{pattern:/\bbackspace\b/gi,keySequence:()=>"backspace"},{pattern:/\bdelete\b/gi,keySequence:()=>"delete"},{pattern:/\bspace\b/gi,keySequence:()=>" "},{pattern:/\barrow\s+(up|down|left|right)\b/gi,keySequence:h=>`arrow_${h[1].toLowerCase()}`},{pattern:/\b(up|down|left|right)\s+arrow\b/gi,keySequence:h=>`arrow_${h[1].toLowerCase()}`},{pattern:/\bpage\s+(up|down)\b/gi,keySequence:h=>`page_${h[1].toLowerCase()}`},{pattern:/\b(home|end)\b/gi,keySequence:h=>h[1].toLowerCase()},{pattern:/\besc\s+to\s+(interrupt|quit|exit|cancel)\b/gi,keySequence:()=>"escape"},{pattern:/\bpress\s+esc\b/gi,keySequence:()=>"escape"},{pattern:/\bpress\s+enter\b/gi,keySequence:()=>"enter"},{pattern:/\bpress\s+tab\b/gi,keySequence:()=>"tab"},{pattern:/\bpress\s+ctrl\+([a-z])\b/gi,keySequence:h=>`ctrl_${h[1].toLowerCase()}`},{pattern:/\bctrl\+([a-z])\s+to\s+\w+/gi,keySequence:h=>`ctrl_${h[1].toLowerCase()}`},{pattern:/\bq\s+to\s+(quit|exit)\b/gi,keySequence:()=>"q"},{pattern:/\bpress\s+q\b/gi,keySequence:()=>"q"},{pattern:/❯\s*(\d+)\.\s+.*/g,keySequence:h=>h[1]},{pattern:/(\d+)\.\s+.*/g,keySequence:h=>h[1]}];function Vs(h,t){new ji(h,t).process()}var ji=class{constructor(t,e){this.processedRanges=new Map;this.container=t,this.lines=t.querySelectorAll(".terminal-line"),this.onShortcutClick=e}process(){if(this.lines.length!==0)for(let t=0;t<this.lines.length;t++)this.processLine(t)}processLine(t){let e=this.getLineText(t);if(!e)return;let i=this.findShortcutsInLine(e);for(let s of i)this.isRangeProcessed(t,s.start,s.end)||(this.createShortcutLink(s,t),this.markRangeAsProcessed(t,s.start,s.end))}findShortcutsInLine(t){let e=[];for(let s of Vr){s.pattern.lastIndex=0;let o=s.pattern.exec(t);for(;o!==null;){let c=o[0],r=s.keySequence(o),a=o.index,g=o.index+c.length;e.push({text:c,keySequence:r,start:a,end:g}),o=s.pattern.exec(t)}}e.sort((s,o)=>s.start-o.start);let i=[];for(let s of e)i.some(c=>s.start<c.end&&s.end>c.start)||i.push(s);return i}createShortcutLink(t,e){let i=this.lines[e];new Yi(i,t,this.onShortcutClick).createLink()}getLineText(t){return t<0||t>=this.lines.length?"":this.lines[t].textContent||""}isRangeProcessed(t,e,i){let s=this.processedRanges.get(t);return s?s.some(o=>e<o.end&&i>o.start):!1}markRangeAsProcessed(t,e,i){this.processedRanges.has(t)||this.processedRanges.set(t,[]);let s=this.processedRanges.get(t);s&&s.push({start:e,end:i})}},Yi=class{constructor(t,e,i){this.lineElement=t,this.shortcut=e,this.onShortcutClick=i}createLink(){this.wrapTextInLink(this.lineElement,this.shortcut.start,this.shortcut.end)}wrapTextInLink(t,e,i){let s=document.createTreeWalker(t,NodeFilter.SHOW_TEXT,null),o=[],c=0,r=s.nextNode();for(;r;){let a=r,g=a.textContent||"",m=c,l=c+g.length;l>e&&m<i&&o.push({node:a,start:m,end:l}),c=l,r=s.nextNode()}for(let a=o.length-1;a>=0;a--){let{node:g,start:m}=o[a],l=g.textContent||"",v=Math.max(0,e-m),f=Math.min(l.length,i-m);v<f&&this.wrapTextNode(g,v,f)}}wrapTextNode(t,e,i){let s=t.parentNode;if(!s||this.isInsideClickable(s))return;let o=t.textContent||"",c=o.substring(0,e),r=o.substring(e,i),a=o.substring(i),g=this.createShortcutElement(r),m=document.createDocumentFragment();c&&m.appendChild(document.createTextNode(c)),m.appendChild(g),a&&m.appendChild(document.createTextNode(a)),s.replaceChild(m,t)}createShortcutElement(t){let e=document.createElement("span");return e.className=qs,e.style.color="#9ca3af",e.style.textDecoration="underline",e.style.textDecorationStyle="dotted",e.style.cursor="pointer",e.style.fontWeight="500",e.textContent=t,e.addEventListener("click",i=>{i.preventDefault(),i.stopPropagation(),this.onShortcutClick(this.shortcut.keySequence)}),e.addEventListener("mouseenter",()=>{e.style.backgroundColor="rgba(156, 163, 175, 0.2)",e.style.color="#d1d5db"}),e.addEventListener("mouseleave",()=>{e.style.backgroundColor="",e.style.color="#9ca3af"}),e.title=`Click to send: ${this.shortcut.keySequence}`,e}isInsideClickable(t){let e=t;for(;e&&e!==document.body;){if(e.tagName==="A"&&e.classList.contains("terminal-link")||e.tagName==="SPAN"&&e.classList.contains(qs))return!0;e=e.parentElement}return!1}};Z();var jr=["https://","http://","file://"],js="terminal-link",fi=/https?:\/\/|file:\/\//g,Yr=/(^|\s)(h|ht|htt|http|https|https:|https:\/|https:\/\/|f|fi|fil|file|file:|file:\/|file:\/\/)$/,Gi=/^[a-zA-Z0-9[\].-]/,Gr=/^[/a-zA-Z0-9[\].-]/,Ys=/[^\w\-._~:/?#[\]@!$&'()*+,;=%{}|\\^`]/,Xr=/^(https?:\/\/(localhost|[\d.]+|\[[\da-fA-F:]+\]|(([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.[a-zA-Z]+))(:\d+)?.*|file:\/\/.+)/,Qr=/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/;function Jr(h){new Xi(h).process()}var Xi=class{constructor(t){this.processedRanges=new Map;this.container=t,this.lines=t.querySelectorAll(".terminal-line")}process(){if(this.lines.length!==0)for(let t=0;t<this.lines.length;t++)this.processLine(t)}processLine(t){t>0&&this.checkPreviousLineContinuation(t),this.findUrlsInLine(t)}checkPreviousLineContinuation(t){let e=this.getLineText(t),i=this.getLineText(t-1),s=this.findIncompleteUrlAtLineEnd(i,e);if(s){let{startPos:o}=s,c=this.buildMultiLineUrl(t-1,o);c&&this.isValidUrl(c.url)&&(this.isRangeProcessed(t-1,o,c.endLine)||(this.createUrlLinks(c.url,t-1,c.endLine,o),this.markRangeAsProcessed(t-1,c.endLine,o,c.url)))}}findIncompleteUrlAtLineEnd(t,e){for(let s of jr){let o=t.lastIndexOf(s);if(o>=0&&t.endsWith(s)&&Gi.test(e.trimStart()))return{startPos:o,protocol:s}}let i=t.match(Yr);if(i){let s=i[2],o=(i.index??0)+(i[1]?1:0);if(this.isValidContinuation(s,e))return{startPos:o,protocol:s}}return null}isValidContinuation(t,e){let i=e.trimStart();if(t==="https://"||t==="file://")return Gi.test(i);if(t.endsWith("/"))return Gr.test(i);let s=t+i;return/^(https?:\/\/|file:\/\/)/.test(s)}isValidUrlContinuation(t,e){let i=e.trimStart();if(!i)return!1;if(!t.includes("://")){let o=t+i;return/^(https?:|file:|https?:\/|file:\/|https?:\/\/|file:\/\/)/.test(o)}if(t.match(/(https?:|file:)\/\/$/))return Gi.test(i);if(/^(and|or|but|the|is|are|was|were|been|have|has|had|will|would|could|should|may|might|check|visit|go|see|click|open|navigate)\b/i.test(i)||/^[!?;]/.test(i)||/^\.(\s|$)/.test(i))return!1;let s=i.split(/\s/)[0];return/[/:._-]/.test(s)?!0:/^[a-zA-Z]+$/.test(s)&&s.length>2?!/^(next|line|with|text|this|that|then|when|where|which|while|after|before|during|since|until|above|below|between|into|through|under|over|about|against|among|around|behind|beside|beyond|inside|outside|toward|within|without|according|although|because|however|therefore|moreover|nevertheless|furthermore|otherwise|meanwhile|indeed|instead|likewise|similarly|specifically|subsequently|ultimately|additionally|consequently|eventually|finally|initially|particularly|previously|recently|suddenly|usually)/i.test(s):/^[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=%-]/.test(i)}findUrlsInLine(t){let e=this.getLineText(t);fi.lastIndex=0;let i=fi.exec(e);for(;i!==null;){let s=i.index;if(this.isPositionProcessed(t,s)){i=fi.exec(e);continue}let o=this.buildMultiLineUrl(t,s);o&&this.isValidUrl(o.url)&&(this.createUrlLinks(o.url,t,o.endLine,s),this.markRangeAsProcessed(t,o.endLine,s,o.url)),i=fi.exec(e)}}buildMultiLineUrl(t,e){let i="",s=t;for(let o=t;o<this.lines.length;o++){let c=this.getLineText(o),r;if(o===t)r=c.substring(e);else{let g=i;if(!this.isValidUrlContinuation(g,c)){s=o-1;break}if(r=c.trimStart(),!r){s=o-1;break}}let a=this.findUrlEndInText(r);if(a>=0){i+=r.substring(0,a),s=o;break}else if(i+=r,s=o,o===this.lines.length-1)break}return{url:this.cleanUrl(i),endLine:s}}findUrlEndInText(t){let e=t.search(/\s/);if(e>=0)return e;let i=t.match(Ys);return i&&i.index!==void 0?i.index:-1}createUrlLinks(t,e,i,s){new Qi(this.lines,t).createLinks(e,i,s)}getLineText(t){return t<0||t>=this.lines.length?"":this.lines[t].textContent||""}isValidUrl(t){if(t.length<7||t.length>2048||/[\n\r\t]/.test(t)||!Xr.test(t))return!1;try{let e=new URL(t);if(!["http:","https:","file:"].includes(e.protocol))return!1;if(e.protocol==="http:"||e.protocol==="https:"){let i=e.hostname;if(i==="localhost"||/^[\d.]+$/.test(i)||i.startsWith("["))return!0;let s=i.split(".");if(s.length<2)return!1;for(let c=0;c<s.length;c++)if(!Qr.test(s[c]))return!1;let o=s[s.length-1];if(!/[a-zA-Z]/.test(o))return!1}return!0}catch{return!1}}cleanUrl(t){let e=t,i=(e.match(/\(/g)||[]).length,s=(e.match(/\)/g)||[]).length;if(s>i){let o=s-i;e=e.replace(/\)+$/,c=>c.substring(0,c.length-o))}return e=e.replace(/[.,;:!?]+$/,""),e}isRangeProcessed(t,e,i){for(let s=t;s<=i;s++)if(this.isPositionProcessed(s,s===t?e:0))return!0;return!1}isPositionProcessed(t,e){let i=this.processedRanges.get(t);return i?i.some(s=>e>=s.start&&e<s.end):!1}markRangeAsProcessed(t,e,i,s){let o=s,c=t;for(;c<=e&&o.length>0;){let r=this.getLineText(c);this.processedRanges.has(c)||this.processedRanges.set(c,[]);let a=this.processedRanges.get(c);if(!a)continue;let g,m;if(c===t){g=i;let l=r.substring(i),v=Math.min(l.length,o.length);m=i+v}else{let l=r.match(/^\s*/);g=l?l[0].length:0;let v=r.substring(g),f=Math.min(v.length,o.length);if(c===e){let b=v.substring(0,f).search(Ys);b>=0&&(f=b)}m=g+f}a.push({start:g,end:m}),o=o.substring(m-g),c++}}},Qi=class{constructor(t,e){this.lines=t,this.url=e}createLinks(t,e,i){let s=this.url;for(let o=t;o<=e;o++){let c=this.lines[o],r=c.textContent||"",a,g;if(o===t){a=i;let m=r.substring(i);g=i+Math.min(m.length,s.length)}else{let m=r.match(/^\s*/);a=m?m[0].length:0;let l=r.substring(a),v=Math.min(l.length,s.length),f=l.match(/[\s<>"'`]/),b=f?Math.min(f.index??v,v):v;g=a+b}if(a<g&&(this.wrapTextInLink(c,a,g),s=s.substring(g-a)),s.length===0)break}}wrapTextInLink(t,e,i){let s=document.createTreeWalker(t,NodeFilter.SHOW_TEXT,null),o=[],c=0,r=s.nextNode();for(;r;){let a=r,g=a.textContent||"",m=c,l=c+g.length;l>e&&m<i&&o.push({node:a,start:m,end:l}),c=l,r=s.nextNode()}for(let a=o.length-1;a>=0;a--){let{node:g,start:m}=o[a],l=g.textContent||"",v=Math.max(0,e-m),f=Math.min(l.length,i-m);v<f&&this.wrapTextNode(g,v,f)}}wrapTextNode(t,e,i){let s=t.parentNode;if(!s||this.isInsideLink(s))return;let o=t.textContent||"",c=o.substring(0,e),r=o.substring(e,i),a=o.substring(i),g=this.createLinkElement(r),m=document.createDocumentFragment();c&&m.appendChild(document.createTextNode(c)),m.appendChild(g),a&&m.appendChild(document.createTextNode(a)),s.replaceChild(m,t)}createLinkElement(t){let e=document.createElement("a");return e.className=js,e.href=this.url,e.target="_blank",e.rel="noopener noreferrer",e.style.color="#4fc3f7",e.style.textDecoration="underline",e.style.cursor="pointer",e.textContent=t,e.addEventListener("mouseenter",()=>{e.style.backgroundColor="rgba(79, 195, 247, 0.2)"}),e.addEventListener("mouseleave",()=>{e.style.backgroundColor=""}),e}isInsideLink(t){let e=t;for(;e&&e!==document.body;){if(e.tagName==="A"&&e.classList.contains(js))return!0;e=e.parentElement}return!1}},Gs={processLinks:Jr};var wt=N("terminal"),ae=class extends F{constructor(){super(...arguments);this.sessionId="";this.sessionStatus="running";this.cols=80;this.rows=24;this.fontSize=14;this.fitHorizontally=!1;this.maxCols=0;this.disableClick=!1;this.hideScrollButton=!1;this.initialCols=0;this.initialRows=0;this.originalFontSize=14;this.userOverrideWidth=!1;this.terminal=null;this._viewportY=0;this.followCursorEnabled=!0;this.programmaticScroll=!1;this.debugMode=!1;this.renderCount=0;this.totalRenderTime=0;this.lastRenderTime=0;this.actualRows=24;this.cursorVisible=!0;this.container=null;this.resizeTimeout=null;this.explicitSizeSet=!1;this.renderPending=!1;this.momentumVelocityY=0;this.momentumVelocityX=0;this.momentumAnimation=null;this.resizeObserver=null;this.operationQueue=[];this.handleScrollToBottom=()=>{this.followCursorEnabled=!0,this.scrollToBottom(),this.requestUpdate()};this.handleFitToggle=()=>{if(!this.terminal||!this.container){this.fitHorizontally=!this.fitHorizontally,this.requestUpdate();return}let e=this.terminal.buffer.active,i=this.fontSize*1.2,s=i>0?this.viewportY/i:0,o=this.isScrolledToBottom();if(this.fitHorizontally||(this.originalFontSize=this.fontSize),this.fitHorizontally=!this.fitHorizontally,this.fitHorizontally||(this.fontSize=this.originalFontSize),this.fitTerminal(),o)this.scrollToBottom();else{let c=this.fontSize*1.2,r=Math.max(0,(e.length-this.actualRows)*c),a=s*c;this.viewportY=Math.max(0,Math.min(r,a))}this.requestUpdate()};this.handlePaste=e=>{e.preventDefault(),e.stopPropagation();let i=e.clipboardData?.getData("text/plain");i&&this.dispatchEvent(new CustomEvent("terminal-paste",{detail:{text:i},bubbles:!0}))};this.handleClick=()=>{this.disableClick||this.container&&this.container.focus()};this.handleShortcutClick=e=>{this.dispatchEvent(new CustomEvent("terminal-input",{detail:{text:e},bubbles:!0}))}}createRenderRoot(){return this}get viewportY(){return this._viewportY}set viewportY(e){this._viewportY=e}queueRenderOperation(e){this.operationQueue.push(e),this.renderPending||(this.renderPending=!0,requestAnimationFrame(()=>{this.processOperationQueue(),this.renderPending=!1}))}requestRenderBuffer(){this.queueRenderOperation(()=>{})}async processOperationQueue(){for(;this.operationQueue.length>0;){let e=this.operationQueue.shift();e&&await e()}this.renderBuffer()}connectedCallback(){if(super.connectedCallback(),this.debugMode=new URLSearchParams(window.location.search).has("debug"),this.sessionId)try{let e=localStorage.getItem(`terminal-width-override-${this.sessionId}`);e!==null&&(this.userOverrideWidth=e==="true")}catch(e){wt.warn("Failed to load terminal width preference from localStorage:",e)}}updated(e){if(e.has("sessionId")&&this.sessionId)try{let i=localStorage.getItem(`terminal-width-override-${this.sessionId}`);i!==null&&(this.userOverrideWidth=i==="true",this.container&&this.fitTerminal())}catch(i){wt.warn("Failed to load terminal width preference from localStorage:",i)}(e.has("cols")||e.has("rows"))&&(this.terminal&&!this.explicitSizeSet&&this.reinitializeTerminal(),this.explicitSizeSet=!1),e.has("fontSize")&&(this.fitHorizontally||(this.originalFontSize=this.fontSize),this.terminal&&this.container&&this.fitTerminal()),e.has("fitHorizontally")&&(this.fitHorizontally||(this.fontSize=this.originalFontSize),this.fitTerminal()),e.has("maxCols")&&this.terminal&&this.container&&this.fitTerminal()}disconnectedCallback(){this.cleanup(),super.disconnectedCallback()}setUserOverrideWidth(e){if(this.userOverrideWidth=e,this.sessionId)try{localStorage.setItem(`terminal-width-override-${this.sessionId}`,String(e))}catch(i){wt.warn("Failed to save terminal width preference to localStorage:",i)}this.container&&this.fitTerminal()}cleanup(){this.momentumAnimation&&(cancelAnimationFrame(this.momentumAnimation),this.momentumAnimation=null),this.resizeObserver&&(this.resizeObserver.disconnect(),this.resizeObserver=null),this.terminal&&(this.terminal.dispose(),this.terminal=null)}firstUpdated(){this.originalFontSize=this.fontSize,this.initializeTerminal()}async initializeTerminal(){try{if(this.requestUpdate(),this.container=this.querySelector("#terminal-container"),!this.container){let e=new Error("Terminal container not found");throw wt.error("terminal container not found",e),e}await this.setupTerminal(),this.setupResize(),this.setupScrolling(),this.requestUpdate()}catch(e){wt.error("failed to initialize terminal:",e),this.requestUpdate()}}async reinitializeTerminal(){if(this.terminal){this.container&&this.container.offsetHeight;let e=Number.isFinite(this.cols)?Math.floor(this.cols):80,i=Number.isFinite(this.rows)?Math.floor(this.rows):24;this.terminal.resize(e,i),this.fitTerminal()}}async setupTerminal(){try{this.terminal=new Xs.Terminal({cursorBlink:!0,cursorStyle:"block",cursorWidth:1,lineHeight:1.2,letterSpacing:0,scrollback:1e4,allowProposedApi:!0,allowTransparency:!1,convertEol:!0,drawBoldTextInBrightColors:!0,minimumContrastRatio:1,macOptionIsMeta:!0,altClickMovesCursor:!0,rightClickSelectsWord:!1,wordSeparator:" ()[]{}'\"`",theme:{background:"#1e1e1e",foreground:"#d4d4d4",cursor:"#00ff00",cursorAccent:"#1e1e1e",black:"#000000",red:"#cd0000",green:"#00cd00",yellow:"#cdcd00",blue:"#0000ee",magenta:"#cd00cd",cyan:"#00cdcd",white:"#e5e5e5",brightBlack:"#7f7f7f",brightRed:"#ff0000",brightGreen:"#00ff00",brightYellow:"#ffff00",brightBlue:"#5c5cff",brightMagenta:"#ff00ff",brightCyan:"#00ffff",brightWhite:"#ffffff"}}),this.terminal.resize(this.cols,this.rows)}catch(e){throw wt.error("failed to create terminal:",e),e}}measureCharacterWidth(){if(!this.container)return 8;let e=document.createElement("div");e.className="terminal-line",e.style.position="absolute",e.style.visibility="hidden",e.style.top="0",e.style.left="0",e.style.fontSize=`${this.fontSize}px`,e.style.fontFamily="Hack Nerd Font Mono, Fira Code, monospace";let i="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?",s=Math.ceil(this.cols/i.length),o=i.repeat(s).substring(0,this.cols);e.textContent=o,this.container.appendChild(e);let r=e.getBoundingClientRect().width/this.cols;return this.container.removeChild(e),Number.isFinite(r)&&r>0?r:8}fitTerminal(){if(!this.terminal||!this.container)return;let e=this.actualRows,i=this.fontSize*1.2,s=this.isScrolledToBottom(),o=i>0?this.viewportY/i:0;if(this.fitHorizontally){let c=this.container.clientWidth,r=this.container.clientHeight,a=c/this.cols,g=this.measureCharacterWidth(),m=a/g,l=this.fontSize*m,v=Math.max(4,Math.min(32,l));this.fontSize=v;let f=this.fontSize*1.2,b=Math.max(1,Math.floor(r/f));if(this.actualRows=b,this.rows=b,this.terminal){let w=Number.isFinite(this.cols)?Math.floor(this.cols):80,n=Number.isFinite(this.rows)?Math.floor(this.rows):24;this.terminal.resize(w,n),this.dispatchEvent(new CustomEvent("terminal-resize",{detail:{cols:this.cols,rows:this.rows},bubbles:!0}))}}else{let c=this.container.clientWidth||800,r=this.container.clientHeight||600,a=this.fontSize*1.2,g=this.measureCharacterWidth(),m=Number.isFinite(g)&&g>0?g:8,l=Math.max(20,Math.floor(c/m))-1,v=this.sessionId.startsWith("fwd_");if(this.maxCols>0?this.cols=Math.min(l,this.maxCols):this.userOverrideWidth?this.cols=l:this.initialCols>0&&v?this.cols=Math.min(l,this.initialCols):this.cols=l,this.rows=Math.max(6,Math.floor(r/a)),this.actualRows=this.rows,this.terminal){let f=Number.isFinite(this.cols)?Math.floor(this.cols):80,b=Number.isFinite(this.rows)?Math.floor(this.rows):24;this.terminal.resize(f,b),this.dispatchEvent(new CustomEvent("terminal-resize",{detail:{cols:this.cols,rows:this.rows},bubbles:!0}))}}if(this.terminal){let c=this.terminal.buffer.active,r=this.fontSize*1.2,a=Math.max(0,(c.length-this.actualRows)*r);if(s)this.viewportY=a;else{let g=o*r,m=Math.max(0,Math.min(a,g));this.viewportY=m}}this.requestRenderBuffer(),this.requestUpdate()}setupResize(){this.container&&(this.resizeObserver=new ResizeObserver(()=>{this.resizeTimeout&&clearTimeout(this.resizeTimeout),this.resizeTimeout=setTimeout(()=>{this.fitTerminal()},50)}),this.resizeObserver.observe(this.container),window.addEventListener("resize",()=>{this.fitTerminal()}))}setupScrolling(){if(!this.container)return;this.container.addEventListener("wheel",m=>{m.preventDefault();let l=this.fontSize*1.2,v=0,f=0;switch(m.deltaMode){case WheelEvent.DOM_DELTA_PIXEL:v=m.deltaY,f=m.deltaX;break;case WheelEvent.DOM_DELTA_LINE:v=m.deltaY*l,f=m.deltaX*l;break;case WheelEvent.DOM_DELTA_PAGE:v=m.deltaY*(this.actualRows*l),f=m.deltaX*(this.actualRows*l);break}let b=.5;v*=b,f*=b,Math.abs(v)>0&&this.scrollViewportPixels(v),Math.abs(f)>0&&!this.fitHorizontally&&this.container&&(this.container.scrollLeft+=f)},{passive:!1});let e=!1,i=0,s=0,o=[],c=m=>{m.pointerType!=="touch"||!m.isPrimary||(this.momentumAnimation&&(cancelAnimationFrame(this.momentumAnimation),this.momentumAnimation=null),e=!1,i=m.clientY,s=m.clientX,o=[{y:m.clientY,x:m.clientX,time:performance.now()}],this.container?.setPointerCapture(m.pointerId))},r=m=>{if(m.pointerType!=="touch"||!this.container?.hasPointerCapture(m.pointerId))return;let l=m.clientY,v=m.clientX,f=i-l,b=s-v,w=performance.now();o.push({y:l,x:v,time:w}),o.length>5&&o.shift(),!e&&(Math.abs(f)>5||Math.abs(b)>5)&&(e=!0),e&&(Math.abs(f)>0&&(this.scrollViewportPixels(f),i=l),Math.abs(b)>0&&!this.fitHorizontally&&(this.container.scrollLeft+=b,s=v))},a=m=>{if(m.pointerType==="touch"){if(e&&o.length>=2){let l=performance.now(),v=o[o.length-1],f=o[o.length-2],b=l-f.time,w=v.y-f.y,n=v.x-f.x,d=b>0?-w/b:0,p=b>0?-n/b:0,u=.3;(Math.abs(d)>u||Math.abs(p)>u)&&this.startMomentum(d,p)}this.container?.releasePointerCapture(m.pointerId)}},g=m=>{m.pointerType==="touch"&&this.container?.releasePointerCapture(m.pointerId)};this.container.addEventListener("pointerdown",c),this.container.addEventListener("pointermove",r),this.container.addEventListener("pointerup",a),this.container.addEventListener("pointercancel",g)}scrollViewport(e){if(!this.terminal)return;let i=this.fontSize*1.2,s=e*i;this.scrollViewportPixels(s)}scrollViewportPixels(e){if(!this.terminal)return;let i=this.terminal.buffer.active,s=this.fontSize*1.2,o=Math.max(0,(i.length-this.actualRows)*s),c=Math.max(0,Math.min(o,this.viewportY+e));c!==this.viewportY&&(this.viewportY=c,this.updateFollowCursorState(),this.requestRenderBuffer())}startMomentum(e,i){this.momentumVelocityY=e*16,this.momentumVelocityX=i*16,this.momentumAnimation&&cancelAnimationFrame(this.momentumAnimation),this.animateMomentum()}animateMomentum(){let s=this.momentumVelocityY,o=this.momentumVelocityX,c=!1;if(Math.abs(s)>.1){let r=this.terminal?.buffer.active;if(r){let a=this.fontSize*1.2,g=Math.max(0,(r.length-this.actualRows)*a),m=Math.max(0,Math.min(g,this.viewportY+s));m!==this.viewportY?(this.viewportY=m,c=!0,this.updateFollowCursorState()):this.momentumVelocityY=0}}if(Math.abs(o)>.1&&!this.fitHorizontally&&this.container){let r=this.container.scrollLeft+o;this.container.scrollLeft=r,c=!0}this.momentumVelocityY*=.92,this.momentumVelocityX*=.92,Math.abs(this.momentumVelocityY)>.1||Math.abs(this.momentumVelocityX)>.1?(this.momentumAnimation=requestAnimationFrame(()=>{this.animateMomentum()}),c&&this.renderBuffer()):(this.momentumAnimation=null,this.momentumVelocityY=0,this.momentumVelocityX=0)}renderBuffer(){if(!this.terminal||!this.container)return;let e=this.debugMode?performance.now():0;this.debugMode&&this.renderCount++;let i=this.terminal.buffer.active,s=i.length,o=this.fontSize*1.2,c=this.viewportY/o,r=Math.floor(c),a=(c-r)*o,g="",m=i.getNullCell(),l=this.terminal.buffer.active.cursorX,v=this.terminal.buffer.active.cursorY+this.terminal.buffer.active.viewportY;for(let f=0;f<this.actualRows;f++){let b=r+f,w=a>0?` style="transform: translateY(-${a}px);"`:"";if(b>=s){g+=`<div class="terminal-line"${w}></div>`;continue}let n=i.getLine(b);if(!n){g+=`<div class="terminal-line"${w}></div>`;continue}let d=b===v,p=this.renderLine(n,m,d&&this.cursorVisible?l:-1);g+=`<div class="terminal-line"${w}>${p||""}</div>`}if(this.container.innerHTML=g,Gs.processLinks(this.container),Vs(this.container,this.handleShortcutClick),this.debugMode){let f=performance.now();this.lastRenderTime=f-e,this.totalRenderTime+=this.lastRenderTime,this.requestUpdate()}}renderLine(e,i,s=-1){let o="",c="",r="",a="",g=l=>l.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"),m=()=>{if(c){let l=g(c);o+=`<span class="${r}"${a?` style="${a}"`:""}>${l}</span>`,c=""}};for(let l=0;l<e.length;l++){if(e.getCell(l,i),!i)continue;let v=i.getChars()||" ";if(i.getWidth()===0)continue;let b="terminal-char",w="",n=l===s;n&&(b+=" cursor");let d=i.getFgColor();if(d!==void 0){if(typeof d=="number"&&d>=0&&d<=255)w+=`color: var(--terminal-color-${d});`;else if(typeof d=="number"&&d>255){let H=d>>16&255,R=d>>8&255,O=d&255;w+=`color: rgb(${H}, ${R}, ${O});`}}let p=i.getBgColor();if(p!==void 0){if(typeof p=="number"&&p>=0&&p<=255)w+=`background-color: var(--terminal-color-${p});`;else if(typeof p=="number"&&p>255){let H=p>>16&255,R=p>>8&255,O=p&255;w+=`background-color: rgb(${H}, ${R}, ${O});`}}let u=i.isBold(),x=i.isItalic(),k=i.isUnderline(),I=i.isDim(),P=i.isInverse(),L=i.isInvisible(),D=i.isStrikethrough(),ie=i.isOverline();if(u&&(b+=" bold"),x&&(b+=" italic"),k&&(b+=" underline"),I&&(b+=" dim"),D&&(b+=" strikethrough"),ie&&(b+=" overline"),P){let H=w.match(/color: ([^;]+);/)?.[1],R=w.match(/background-color: ([^;]+);/)?.[1],O="#e4e4e4",Ie="#0a0a0a",Se=H||O,G=R||Ie;w="",w+=`color: ${G};`,w+=`background-color: ${Se};`}n&&(w+="background-color: #23d18b;"),L&&(w+="opacity: 0;"),(b!==r||w!==a)&&(m(),r=b,a=w),c+=v}return m(),o}write(e,i=!0){this.terminal&&(e.includes("\x1B[?25l")&&(this.cursorVisible=!1),e.includes("\x1B[?25h")&&(this.cursorVisible=!0),this.queueRenderOperation(async()=>{if(this.terminal&&(await new Promise(s=>{this.terminal?this.terminal.write(e,s):s()}),i&&this.followCursorEnabled)){let s=this.terminal.buffer.active,o=this.fontSize*1.2,c=Math.max(0,(s.length-this.actualRows)*o);this.programmaticScroll=!0,this.viewportY=c,this.programmaticScroll=!1}}))}clear(){this.terminal&&this.queueRenderOperation(()=>{this.terminal&&(this.terminal.clear(),this.viewportY=0)})}setTerminalSize(e,i){this.cols=e,this.rows=i,this.terminal&&(this.explicitSizeSet=!0,this.queueRenderOperation(()=>{this.terminal&&(this.terminal.resize(e,i),this.requestUpdate())}))}scrollToBottom(){this.terminal&&this.queueRenderOperation(()=>{if(!this.terminal)return;this.fitTerminal();let e=this.terminal.buffer.active,i=this.fontSize*1.2,s=Math.max(0,(e.length-this.actualRows)*i);this.programmaticScroll=!0,this.viewportY=s,this.programmaticScroll=!1})}scrollToPosition(e){this.terminal&&this.queueRenderOperation(()=>{if(!this.terminal)return;let i=this.terminal.buffer.active,s=this.fontSize*1.2,o=Math.max(0,i.length-this.actualRows);this.programmaticScroll=!0,this.viewportY=Math.max(0,Math.min(o,e))*s,this.programmaticScroll=!1})}queueCallback(e){this.queueRenderOperation(e)}getTerminalSize(){return{cols:this.cols,rows:this.rows}}getVisibleRows(){return this.actualRows}getBufferSize(){return this.terminal?this.terminal.buffer.active.length:0}getScrollPosition(){let e=this.fontSize*1.2;return Math.round(this.viewportY/e)}getMaxScrollPosition(){if(!this.terminal)return 0;let e=this.terminal.buffer.active;return Math.max(0,e.length-this.actualRows)}followCursor(){if(!this.terminal)return;let e=this.terminal.buffer.active,i=e.cursorY+e.viewportY,s=this.fontSize*1.2,o=i,c=Math.floor(this.viewportY/s),r=c+this.actualRows-1;this.programmaticScroll=!0,o<c?this.viewportY=o*s:o>r&&(this.viewportY=Math.max(0,(o-this.actualRows+1)*s));let a=Math.max(0,(e.length-this.actualRows)*s);this.viewportY=Math.min(this.viewportY,a),this.programmaticScroll=!1}isScrolledToBottom(){if(!this.terminal)return!0;let e=this.terminal.buffer.active,i=this.fontSize*1.2,s=Math.max(0,(e.length-this.actualRows)*i);return this.viewportY>=s-i}updateFollowCursorState(){if(this.programmaticScroll)return;let e=this.isScrolledToBottom();e&&!this.followCursorEnabled?this.followCursorEnabled=!0:!e&&this.followCursorEnabled&&(this.followCursorEnabled=!1)}render(){return S`
      <style>
        /* Dynamic terminal sizing */
        .terminal-container {
          font-size: ${this.fontSize}px;
          line-height: ${this.fontSize*1.2}px;
          touch-action: none !important;
        }

        .terminal-line {
          height: ${this.fontSize*1.2}px;
          line-height: ${this.fontSize*1.2}px;
        }
      </style>
      <div class="relative w-full h-full p-0 m-0">
        <div
          id="terminal-container"
          class="terminal-container w-full h-full overflow-hidden p-0 m-0"
          tabindex="0"
          contenteditable="false"
          style="view-transition-name: session-${this.sessionId}"
          @paste=${this.handlePaste}
          @click=${this.handleClick}
          data-testid="terminal-container"
        ></div>
        ${!this.followCursorEnabled&&!this.hideScrollButton?S`
              <div
                class="scroll-to-bottom"
                @click=${this.handleScrollToBottom}
                title="Scroll to bottom"
              >
                ↓
              </div>
            `:""}
        ${this.debugMode?S`
              <div class="debug-overlay">
                <div class="metric">
                  <span class="metric-label">Renders:</span>
                  <span class="metric-value">${this.renderCount}</span>
                </div>
                <div class="metric">
                  <span class="metric-label">Avg:</span>
                  <span class="metric-value"
                    >${this.renderCount>0?(this.totalRenderTime/this.renderCount).toFixed(2):"0.00"}ms</span
                  >
                </div>
                <div class="metric">
                  <span class="metric-label">Last:</span>
                  <span class="metric-value">${this.lastRenderTime.toFixed(2)}ms</span>
                </div>
              </div>
            `:""}
      </div>
    `}};_([$({type:String})],ae.prototype,"sessionId",2),_([$({type:String})],ae.prototype,"sessionStatus",2),_([$({type:Number})],ae.prototype,"cols",2),_([$({type:Number})],ae.prototype,"rows",2),_([$({type:Number})],ae.prototype,"fontSize",2),_([$({type:Boolean})],ae.prototype,"fitHorizontally",2),_([$({type:Number})],ae.prototype,"maxCols",2),_([$({type:Boolean})],ae.prototype,"disableClick",2),_([$({type:Boolean})],ae.prototype,"hideScrollButton",2),_([$({type:Number})],ae.prototype,"initialCols",2),_([$({type:Number})],ae.prototype,"initialRows",2),_([A()],ae.prototype,"terminal",2),_([A()],ae.prototype,"followCursorEnabled",2),_([A()],ae.prototype,"actualRows",2),_([A()],ae.prototype,"cursorVisible",2),ae=_([z("vibe-terminal")],ae);var Ji=[{key:"Escape",label:"Esc",row:1},{key:"Control",label:"Ctrl",modifier:!0,row:1},{key:"CtrlExpand",label:"\u2303",toggle:!0,row:1},{key:"F",label:"F",toggle:!0,row:1},{key:"Tab",label:"Tab",row:1},{key:"shift_tab",label:"\u21E4",row:1},{key:"ArrowUp",label:"\u2191",arrow:!0,row:1},{key:"ArrowDown",label:"\u2193",arrow:!0,row:1},{key:"ArrowLeft",label:"\u2190",arrow:!0,row:1},{key:"ArrowRight",label:"\u2192",arrow:!0,row:1},{key:"PageUp",label:"PgUp",row:1},{key:"PageDown",label:"PgDn",row:1},{key:"Home",label:"Home",row:2},{key:"End",label:"End",row:2},{key:"Delete",label:"Del",row:2},{key:"`",label:"`",row:2},{key:"~",label:"~",row:2},{key:"|",label:"|",row:2},{key:"/",label:"/",row:2},{key:"\\",label:"\\",row:2},{key:"-",label:"-",row:2},{key:"Done",label:"Done",special:!0,row:2},{key:"Option",label:"\u2325",modifier:!0,row:3},{key:"Command",label:"\u2318",modifier:!0,row:3},{key:"Ctrl+C",label:"^C",combo:!0,row:3},{key:"Ctrl+Z",label:"^Z",combo:!0,row:3},{key:"'",label:"'",row:3},{key:'"',label:'"',row:3},{key:"{",label:"{",row:3},{key:"}",label:"}",row:3},{key:"[",label:"[",row:3},{key:"]",label:"]",row:3},{key:"(",label:"(",row:3},{key:")",label:")",row:3}],Zr=[{key:"Ctrl+D",label:"^D",combo:!0,description:"EOF/logout"},{key:"Ctrl+L",label:"^L",combo:!0,description:"Clear screen"},{key:"Ctrl+R",label:"^R",combo:!0,description:"Reverse search"},{key:"Ctrl+W",label:"^W",combo:!0,description:"Delete word"},{key:"Ctrl+U",label:"^U",combo:!0,description:"Clear line"},{key:"Ctrl+A",label:"^A",combo:!0,description:"Start of line"},{key:"Ctrl+E",label:"^E",combo:!0,description:"End of line"},{key:"Ctrl+K",label:"^K",combo:!0,description:"Kill to EOL"},{key:"CtrlFull",label:"Ctrl\u2026",special:!0,description:"Full Ctrl UI"}],en=Array.from({length:12},(h,t)=>({key:`F${t+1}`,label:`F${t+1}`,func:!0})),He=class extends F{constructor(){super(...arguments);this.visible=!1;this.keyboardHeight=0;this.showFunctionKeys=!1;this.showCtrlKeys=!1;this.isLandscape=!1;this.keyRepeatInterval=null;this.keyRepeatTimeout=null;this.orientationHandler=null}createRenderRoot(){return this}connectedCallback(){super.connectedCallback(),this.checkOrientation(),this.orientationHandler=()=>{this.checkOrientation()},window.addEventListener("resize",this.orientationHandler),window.addEventListener("orientationchange",this.orientationHandler)}checkOrientation(){this.isLandscape=window.innerWidth>window.innerHeight&&window.innerWidth>600}updated(e){super.updated(e),e.has("keyboardHeight")&&console.log("[QuickKeys] Keyboard height changed:",this.keyboardHeight)}handleKeyPress(e,i=!1,s=!1,o=!1,c){if(c&&(c.preventDefault(),c.stopPropagation()),o&&e==="F"){this.showFunctionKeys=!this.showFunctionKeys,this.showCtrlKeys=!1;return}if(o&&e==="CtrlExpand"){this.showCtrlKeys=!this.showCtrlKeys,this.showFunctionKeys=!1;return}this.showFunctionKeys&&e.startsWith("F")&&e!=="F"&&(this.showFunctionKeys=!1),this.showCtrlKeys&&e.startsWith("Ctrl+")&&(this.showCtrlKeys=!1),this.onKeyPress&&this.onKeyPress(e,i,s)}startKeyRepeat(e,i,s){e.startsWith("Arrow")&&(this.stopKeyRepeat(),this.onKeyPress&&this.onKeyPress(e,i,s),this.keyRepeatTimeout=window.setTimeout(()=>{this.keyRepeatInterval=window.setInterval(()=>{this.onKeyPress&&this.onKeyPress(e,i,s)},50)},500))}stopKeyRepeat(){this.keyRepeatTimeout&&(clearTimeout(this.keyRepeatTimeout),this.keyRepeatTimeout=null),this.keyRepeatInterval&&(clearInterval(this.keyRepeatInterval),this.keyRepeatInterval=null)}disconnectedCallback(){super.disconnectedCallback(),this.stopKeyRepeat(),this.orientationHandler&&(window.removeEventListener("resize",this.orientationHandler),window.removeEventListener("orientationchange",this.orientationHandler),this.orientationHandler=null)}render(){if(!this.visible)return"";let e=this.keyboardHeight>0?`${this.keyboardHeight}px`:null;return S`
      <div 
        class="terminal-quick-keys-container"
        style=${e?`bottom: ${e}`:""}
        @mousedown=${i=>i.preventDefault()}
        @touchstart=${i=>i.preventDefault()}
      >
        <div class="quick-keys-bar">
          <!-- Row 1 -->
          <div class="flex gap-1 justify-center mb-1">
            ${Ji.filter(i=>i.row===1).map(({key:i,label:s,modifier:o,arrow:c,toggle:r})=>S`
                <button
                  type="button"
                  tabindex="-1"
                  class="quick-key-btn flex-1 min-w-0 px-0.5 ${this.isLandscape?"py-1":"py-1.5"} bg-dark-bg-tertiary text-dark-text text-xs font-mono rounded border border-dark-border hover:bg-dark-surface hover:border-accent-green transition-all whitespace-nowrap ${o?"modifier-key":""} ${c?"arrow-key":""} ${r?"toggle-key":""} ${r&&(i==="CtrlExpand"&&this.showCtrlKeys||i==="F"&&this.showFunctionKeys)?"active":""}"
                  @mousedown=${a=>{a.preventDefault(),a.stopPropagation()}}
                  @touchstart=${a=>{a.preventDefault(),a.stopPropagation(),c&&this.startKeyRepeat(i,o||!1,!1)}}
                  @touchend=${a=>{a.preventDefault(),a.stopPropagation(),c?this.stopKeyRepeat():this.handleKeyPress(i,o,!1,r,a)}}
                  @touchcancel=${a=>{c&&this.stopKeyRepeat()}}
                  @click=${a=>{a.detail!==0&&!c&&this.handleKeyPress(i,o,!1,r,a)}}
                >
                  ${s}
                </button>
              `)}
          </div>
          
          <!-- Row 2 or Function Keys or Ctrl Shortcuts -->
          ${this.showCtrlKeys?S`
              <!-- Ctrl shortcuts row -->
              <div class="flex gap-1 justify-between flex-wrap mb-1">
                ${Zr.map(({key:i,label:s,combo:o,special:c})=>S`
                    <button
                      type="button"
                      tabindex="-1"
                      class="ctrl-shortcut-btn flex-1 min-w-0 px-0.5 ${this.isLandscape?"py-1":"py-1.5"} bg-dark-bg-tertiary text-dark-text text-xs font-mono rounded border border-dark-border hover:bg-dark-surface hover:border-accent-green transition-all whitespace-nowrap ${o?"combo-key":""} ${c?"special-key":""}"
                      @mousedown=${r=>{r.preventDefault(),r.stopPropagation()}}
                      @touchstart=${r=>{r.preventDefault(),r.stopPropagation()}}
                      @touchend=${r=>{r.preventDefault(),r.stopPropagation(),this.handleKeyPress(i,!1,c,!1,r)}}
                      @click=${r=>{r.detail!==0&&this.handleKeyPress(i,!1,c,!1,r)}}
                    >
                      ${s}
                    </button>
                  `)}
              </div>
            `:this.showFunctionKeys?S`
              <!-- Function keys row -->
              <div class="flex gap-1 justify-between mb-1">
                ${en.map(({key:i,label:s})=>S`
                    <button
                      type="button"
                      tabindex="-1"
                      class="func-key-btn flex-1 min-w-0 px-0.5 ${this.isLandscape?"py-1":"py-1.5"} bg-dark-bg-tertiary text-dark-text text-xs font-mono rounded border border-dark-border hover:bg-dark-surface hover:border-accent-green transition-all whitespace-nowrap"
                      @mousedown=${o=>{o.preventDefault(),o.stopPropagation()}}
                      @touchstart=${o=>{o.preventDefault(),o.stopPropagation()}}
                      @touchend=${o=>{o.preventDefault(),o.stopPropagation(),this.handleKeyPress(i,!1,!1,!1,o)}}
                      @click=${o=>{o.detail!==0&&this.handleKeyPress(i,!1,!1,!1,o)}}
                    >
                      ${s}
                    </button>
                  `)}
              </div>
            `:S`
              <!-- Regular row 2 -->
              <div class="flex gap-1 justify-center mb-1">
                ${Ji.filter(i=>i.row===2).map(({key:i,label:s,modifier:o,combo:c,special:r,toggle:a})=>S`
                    <button
                      type="button"
                      tabindex="-1"
                      class="quick-key-btn flex-1 min-w-0 px-0.5 ${this.isLandscape?"py-1":"py-1.5"} bg-dark-bg-tertiary text-dark-text text-xs font-mono rounded border border-dark-border hover:bg-dark-surface hover:border-accent-green transition-all whitespace-nowrap ${o?"modifier-key":""} ${c?"combo-key":""} ${r?"special-key":""} ${a?"toggle-key":""} ${a&&this.showFunctionKeys?"active":""}"
                      @mousedown=${g=>{g.preventDefault(),g.stopPropagation()}}
                      @touchstart=${g=>{g.preventDefault(),g.stopPropagation()}}
                      @touchend=${g=>{g.preventDefault(),g.stopPropagation(),this.handleKeyPress(i,o||c,r,a,g)}}
                      @click=${g=>{g.detail!==0&&this.handleKeyPress(i,o||c,r,a,g)}}
                    >
                      ${s}
                    </button>
                  `)}
              </div>
            `}
          
          <!-- Row 3 - Additional special characters (always visible) -->
          <div class="flex gap-1 justify-center text-xs">
            ${Ji.filter(i=>i.row===3).map(({key:i,label:s,modifier:o,combo:c,special:r})=>S`
                <button
                  type="button"
                  tabindex="-1"
                  class="quick-key-btn flex-1 min-w-0 px-0.5 ${this.isLandscape?"py-0.5":"py-1"} bg-dark-bg-tertiary text-dark-text text-xs font-mono rounded border border-dark-border hover:bg-dark-surface hover:border-accent-green transition-all whitespace-nowrap ${o?"modifier-key":""} ${c?"combo-key":""} ${r?"special-key":""}"
                  @mousedown=${a=>{a.preventDefault(),a.stopPropagation()}}
                  @touchstart=${a=>{a.preventDefault(),a.stopPropagation()}}
                  @touchend=${a=>{a.preventDefault(),a.stopPropagation(),this.handleKeyPress(i,o||c,r,!1,a)}}
                  @click=${a=>{a.detail!==0&&this.handleKeyPress(i,o||c,r,!1,a)}}
                >
                  ${s}
                </button>
              `)}
          </div>
        </div>
      </div>
      <style>
        /* Hide scrollbar */
        .scrollbar-hide {
          -ms-overflow-style: none;
          scrollbar-width: none;
          overflow-x: auto !important;
          overflow-y: hidden;
          -webkit-overflow-scrolling: touch;
        }
        .scrollbar-hide::-webkit-scrollbar {
          display: none;
        }
        
        /* Quick keys container - positioned above keyboard */
        .terminal-quick-keys-container {
          position: fixed;
          left: 0;
          right: 0;
          /* Chrome: Use env() if supported */
          bottom: env(keyboard-inset-height, 0px);
          /* Safari: Will be overridden by inline style */
          z-index: 999999;
          /* Ensure it stays on top */
          isolation: isolate;
          /* Smooth transition when keyboard appears/disappears */
          transition: bottom 0.3s ease-out;
        }
        
        /* The actual bar with buttons */
        .quick-keys-bar {
          background: rgb(17, 17, 17);
          border-top: 1px solid rgb(51, 51, 51);
          padding: 0.5rem 0.25rem;
          /* Prevent iOS from adding its own styling */
          -webkit-appearance: none;
          appearance: none;
          /* Add shadow for visibility */
          box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.5);
        }
        
        /* Quick key buttons */
        .quick-key-btn {
          outline: none !important;
          -webkit-tap-highlight-color: transparent;
          user-select: none;
          -webkit-user-select: none;
          /* Ensure buttons are clickable */
          touch-action: manipulation;
        }
        
        /* Modifier key styling */
        .modifier-key {
          background-color: #1a1a1a;
          border-color: #444;
        }
        
        .modifier-key:hover {
          background-color: #2a2a2a;
        }
        
        /* Arrow key styling */
        .arrow-key {
          font-size: 1rem;
          padding: 0.375rem 0.5rem;
        }
        
        /* Combo key styling (like ^C, ^Z) */
        .combo-key {
          background-color: #1e1e1e;
          border-color: #555;
        }
        
        .combo-key:hover {
          background-color: #2e2e2e;
        }
        
        /* Special key styling (like ABC) */
        .special-key {
          background-color: rgb(0, 122, 255);
          border-color: rgb(0, 122, 255);
          color: white;
        }
        
        .special-key:hover {
          background-color: rgb(0, 100, 220);
        }
        
        /* Function key styling */
        .func-key-btn {
          outline: none !important;
          -webkit-tap-highlight-color: transparent;
          user-select: none;
          -webkit-user-select: none;
          touch-action: manipulation;
        }
        
        /* Toggle button styling */
        .toggle-key {
          background-color: #2a2a2a;
          border-color: #666;
        }
        
        .toggle-key:hover {
          background-color: #3a3a3a;
        }
        
        .toggle-key.active {
          background-color: rgb(0, 122, 255);
          border-color: rgb(0, 122, 255);
          color: white;
        }
        
        .toggle-key.active:hover {
          background-color: rgb(0, 100, 220);
        }
        
        /* Ctrl shortcut button styling */
        .ctrl-shortcut-btn {
          outline: none !important;
          -webkit-tap-highlight-color: transparent;
          user-select: none;
          -webkit-user-select: none;
          touch-action: manipulation;
        }
        
        /* Landscape mode adjustments - reduce height/padding by 10% */
        @media (orientation: landscape) and (max-width: 926px) {
          .quick-keys-bar {
            padding: 0.45rem 0.225rem; /* 10% less than 0.5rem 0.25rem */
          }
          
          .quick-key-btn {
            padding: 0.3375rem 0.45rem; /* 10% less than py-1.5 (0.375rem) px-0.5 (0.125rem) */
          }
          
          .arrow-key {
            padding: 0.3375rem 0.45rem; /* 10% less than 0.375rem 0.5rem */
          }
          
          .ctrl-shortcut-btn, .func-key-btn {
            padding: 0.3375rem 0.45rem; /* 10% less than py-1.5 px-0.5 */
          }
          
          /* Row 3 buttons with py-1 become 10% less */
          .quick-keys-bar .flex.gap-1.justify-center.text-xs button {
            padding: 0.225rem 0.45rem; /* 10% less than py-1 (0.25rem) px-0.5 */
          }
        }
      </style>
    `}};_([$({type:Function})],He.prototype,"onKeyPress",2),_([$({type:Boolean})],He.prototype,"visible",2),_([$({type:Number})],He.prototype,"keyboardHeight",2),_([A()],He.prototype,"showFunctionKeys",2),_([A()],He.prototype,"showCtrlKeys",2),_([A()],He.prototype,"isLandscape",2),He=_([z("terminal-quick-keys")],He);Z();var Qs=N("mobile-input-overlay"),be=class extends F{constructor(){super(...arguments);this.visible=!1;this.mobileInputText="";this.keyboardHeight=0;this.touchStartX=0;this.touchStartY=0;this.isComposing=!1;this.compositionBuffer="";this.touchStartHandler=e=>{let i=e.touches[0];this.touchStartX=i.clientX,this.touchStartY=i.clientY};this.touchEndHandler=e=>{let i=e.changedTouches[0],s=i.clientX,o=i.clientY,c=s-this.touchStartX,r=o-this.touchStartY,a=c>100,g=Math.abs(r)<100,m=this.touchStartX<50;a&&g&&m&&this.handleBack&&this.handleBack()};this.handleCompositionStart=e=>{this.isComposing=!0,this.compositionBuffer=""};this.handleCompositionUpdate=e=>{this.compositionBuffer=e.data||""};this.handleCompositionEnd=e=>{this.isComposing=!1;let i=e.data||"",s=e.target;s&&i&&(this.mobileInputText=s.value,this.onTextChange?.(s.value),this.requestUpdate()),this.compositionBuffer=""}}createRenderRoot(){return this}handleMobileInputChange(e){let i=e.target;this.isComposing||(this.mobileInputText=i.value,this.onTextChange?.(i.value),this.requestUpdate())}focusMobileTextarea(){let e=this.querySelector("#mobile-input-textarea");e&&(e.focus(),e.setAttribute("readonly","readonly"),e.focus(),setTimeout(()=>{e.removeAttribute("readonly"),e.focus(),e.setSelectionRange(e.value.length,e.value.length)},100))}async handleMobileInputSendOnly(){let e=this.querySelector("#mobile-input-textarea"),i=e?.value?.trim()||this.mobileInputText.trim();i&&(this.onSend?.(i),this.mobileInputText="",e&&(e.value=""),this.requestUpdate())}async handleMobileInputSend(){let e=this.querySelector("#mobile-input-textarea"),i=e?.value?.trim()||this.mobileInputText.trim();i&&(this.onSendWithEnter?.(i),this.mobileInputText="",e&&(e.value=""),this.requestUpdate())}handleKeydown(e){e.key==="Enter"&&(e.ctrlKey||e.metaKey)?(e.preventDefault(),this.handleMobileInputSend()):e.key==="Escape"&&(e.preventDefault(),this.onCancel?.())}handleFocus(e){e.stopPropagation(),Qs.log("Mobile input textarea focused")}handleBlur(e){e.stopPropagation(),Qs.log("Mobile input textarea blurred")}handleBackdropClick(e){e.target===e.currentTarget&&this.onCancel?.()}handleContainerClick(e){e.stopPropagation(),this.focusMobileTextarea()}updated(){this.visible&&setTimeout(()=>{this.focusMobileTextarea()},100)}render(){return this.visible?S`
      <div
        class="fixed inset-0 z-40 flex flex-col"
        style="background: rgba(0, 0, 0, 0.8);"
        @click=${this.handleBackdropClick}
        @touchstart=${this.touchStartHandler}
        @touchend=${this.touchEndHandler}
      >
        <!-- Spacer to push content up above keyboard -->
        <div class="flex-1"></div>

        <div
          class="mobile-input-container font-mono text-sm mx-4 flex flex-col"
          style="background: black; border: 1px solid #569cd6; border-radius: 8px; margin-bottom: ${this.keyboardHeight>0?`${this.keyboardHeight+180}px`:"calc(env(keyboard-inset-height, 0px) + 180px)"};/* 180px = estimated quick keyboard height (3 rows) */"
          @click=${this.handleContainerClick}
        >
          <!-- Input Area -->
          <div class="p-4 flex flex-col">
            <textarea
              id="mobile-input-textarea"
              class="w-full font-mono text-sm resize-none outline-none"
              placeholder="Type your command here..."
              .value=${this.mobileInputText}
              @input=${this.handleMobileInputChange}
              @focus=${this.handleFocus}
              @blur=${this.handleBlur}
              @keydown=${this.handleKeydown}
              @compositionstart=${this.handleCompositionStart}
              @compositionupdate=${this.handleCompositionUpdate}
              @compositionend=${this.handleCompositionEnd}
              style="height: 120px; background: black; color: #d4d4d4; border: none; padding: 12px;"
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck="false"
            ></textarea>
          </div>

          <!-- Controls -->
          <div class="p-4 flex gap-2" style="border-top: 1px solid #444;">
            <button
              class="font-mono px-3 py-2 text-xs transition-colors btn-ghost"
              @click=${()=>this.onCancel?.()}
            >
              CANCEL
            </button>
            <button
              class="flex-1 font-mono px-3 py-2 text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed btn-ghost"
              @click=${this.handleMobileInputSendOnly}
              ?disabled=${!this.mobileInputText.trim()}
            >
              SEND
            </button>
            <button
              class="flex-1 font-mono px-3 py-2 text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed btn-secondary"
              @click=${this.handleMobileInputSend}
              ?disabled=${!this.mobileInputText.trim()}
            >
              SEND + ⏎
            </button>
          </div>
        </div>
      </div>
    `:null}};_([$({type:Boolean})],be.prototype,"visible",2),_([$({type:String})],be.prototype,"mobileInputText",2),_([$({type:Number})],be.prototype,"keyboardHeight",2),_([$({type:Number})],be.prototype,"touchStartX",2),_([$({type:Number})],be.prototype,"touchStartY",2),_([$({type:Function})],be.prototype,"onSend",2),_([$({type:Function})],be.prototype,"onSendWithEnter",2),_([$({type:Function})],be.prototype,"onCancel",2),_([$({type:Function})],be.prototype,"onTextChange",2),_([$({type:Function})],be.prototype,"handleBack",2),be=_([z("mobile-input-overlay")],be);var Ae=class extends F{constructor(){super(...arguments);this.visible=!1;this.ctrlSequence=[];this.keyboardHeight=0}createRenderRoot(){return this}handleBackdropClick(e){e.target===e.currentTarget&&this.onCancel?.()}handleCtrlKey(e){this.onCtrlKey?.(e)}render(){return this.visible?S`
      <div
        class="fixed inset-0 z-50 flex flex-col"
        style="background: rgba(0, 0, 0, 0.8);"
        @click=${this.handleBackdropClick}
      >
        <!-- Spacer to push content up above keyboard -->
        <div class="flex-1"></div>
        
        <div
          class="font-mono text-sm mx-4 max-w-sm w-full self-center"
          style="background: black; border: 1px solid #569cd6; border-radius: 8px; padding: 10px; margin-bottom: ${this.keyboardHeight>0?`${this.keyboardHeight+180}px`:"calc(env(keyboard-inset-height, 0px) + 180px)"};/* 180px = estimated quick keyboard height (3 rows) */"
          @click=${e=>e.stopPropagation()}
        >
          <div class="text-vs-user text-center mb-2 font-bold">Ctrl + Key</div>

          <!-- Help text -->
          <div class="text-xs text-vs-muted text-center mb-3 opacity-70">
            Build sequences like ctrl+c ctrl+c
          </div>

          <!-- Current sequence display -->
          ${this.ctrlSequence.length>0?S`
                <div class="text-center mb-4 p-2 border border-vs-muted rounded bg-vs-bg">
                  <div class="text-xs text-vs-muted mb-1">Current sequence:</div>
                  <div class="text-sm text-vs-accent font-bold">
                    ${this.ctrlSequence.map(e=>`Ctrl+${e}`).join(" ")}
                  </div>
                </div>
              `:""}

          <!-- Grid of A-Z buttons -->
          <div class="grid grid-cols-6 gap-1 mb-3">
            ${["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"].map(e=>S`
                <button
                  class="font-mono text-xs transition-all cursor-pointer aspect-square flex items-center justify-center quick-start-btn py-2"
                  @click=${()=>this.handleCtrlKey(e)}
                >
                  ${e}
                </button>
              `)}
          </div>

          <!-- Common shortcuts info -->
          <div class="text-xs text-vs-muted text-center mb-3">
            <div>Common: C=interrupt, X=exit, O=save, W=search</div>
          </div>

          <!-- Action buttons -->
          <div class="flex gap-2 justify-center">
            <button
              class="font-mono px-4 py-2 text-sm transition-all cursor-pointer btn-ghost"
              @click=${()=>this.onCancel?.()}
            >
              CANCEL
            </button>
            ${this.ctrlSequence.length>0?S`
                  <button
                    class="font-mono px-3 py-2 text-sm transition-all cursor-pointer btn-ghost"
                    @click=${()=>this.onClearSequence?.()}
                  >
                    CLEAR
                  </button>
                  <button
                    class="font-mono px-3 py-2 text-sm transition-all cursor-pointer btn-secondary"
                    @click=${()=>this.onSendSequence?.()}
                  >
                    SEND
                  </button>
                `:""}
          </div>
        </div>
      </div>
    `:null}};_([$({type:Boolean})],Ae.prototype,"visible",2),_([$({type:Array})],Ae.prototype,"ctrlSequence",2),_([$({type:Number})],Ae.prototype,"keyboardHeight",2),_([$({type:Function})],Ae.prototype,"onCtrlKey",2),_([$({type:Function})],Ae.prototype,"onSendSequence",2),_([$({type:Function})],Ae.prototype,"onClearSequence",2),_([$({type:Function})],Ae.prototype,"onCancel",2),Ae=_([z("ctrl-alpha-overlay")],Ae);Z();var Js=N("terminal-preferences"),mi=[{value:0,label:"\u221E",description:"Unlimited (full width)"},{value:80,label:"80",description:"Classic terminal"},{value:100,label:"100",description:"Modern standard"},{value:120,label:"120",description:"Wide terminal"},{value:132,label:"132",description:"Mainframe width"},{value:160,label:"160",description:"Ultra-wide"}],Zi={maxCols:0,fontSize:14,fitHorizontally:!1},Zs="vibetunnel_terminal_preferences",gi=class h{constructor(){this.preferences=this.loadPreferences()}static getInstance(){return h.instance||(h.instance=new h),h.instance}loadPreferences(){try{let t=localStorage.getItem(Zs);if(t){let e=JSON.parse(t);return{...Zi,...e}}}catch(t){Js.warn("Failed to load terminal preferences",{error:t})}return{...Zi}}savePreferences(){try{localStorage.setItem(Zs,JSON.stringify(this.preferences))}catch(t){Js.warn("Failed to save terminal preferences",{error:t})}}getMaxCols(){return this.preferences.maxCols}setMaxCols(t){this.preferences.maxCols=Math.max(0,t),this.savePreferences()}getFontSize(){return this.preferences.fontSize}setFontSize(t){this.preferences.fontSize=Math.max(8,Math.min(32,t)),this.savePreferences()}getFitHorizontally(){return this.preferences.fitHorizontally}setFitHorizontally(t){this.preferences.fitHorizontally=t,this.savePreferences()}getPreferences(){return{...this.preferences}}resetToDefaults(){this.preferences={...Zi},this.savePreferences()}};var $e=class extends F{constructor(){super(...arguments);this.visible=!1;this.terminalMaxCols=0;this.terminalFontSize=14;this.customWidth=""}createRenderRoot(){return this}handleCustomWidthInput(e){let i=e.target;this.customWidth=i.value,this.requestUpdate()}handleCustomWidthSubmit(){let e=Number.parseInt(this.customWidth,10);!Number.isNaN(e)&&e>=20&&e<=500&&(this.onWidthSelect?.(e),this.customWidth="")}handleCustomWidthKeydown(e){e.key==="Enter"?this.handleCustomWidthSubmit():e.key==="Escape"&&(this.customWidth="",this.onClose?.())}render(){return this.visible?S`
      <div
        class="width-selector-container absolute top-8 right-0 bg-dark-bg-secondary border border-dark-border rounded-md shadow-lg z-50 min-w-48"
      >
        <div class="p-2">
          <div class="text-xs text-dark-text-muted mb-2 px-2">Terminal Width</div>
          ${mi.map(e=>S`
              <button
                class="w-full text-left px-2 py-1 text-xs hover:bg-dark-border rounded-sm flex justify-between items-center
                  ${this.terminalMaxCols===e.value?"bg-dark-border text-accent-green":"text-dark-text"}"
                @click=${()=>this.onWidthSelect?.(e.value)}
              >
                <span class="font-mono">${e.label}</span>
                <span class="text-dark-text-muted text-xs">${e.description}</span>
              </button>
            `)}
          <div class="border-t border-dark-border mt-2 pt-2">
            <div class="text-xs text-dark-text-muted mb-1 px-2">Custom (20-500)</div>
            <div class="flex gap-1">
              <input
                type="number"
                min="20"
                max="500"
                placeholder="80"
                .value=${this.customWidth}
                @input=${this.handleCustomWidthInput}
                @keydown=${this.handleCustomWidthKeydown}
                @click=${e=>e.stopPropagation()}
                class="flex-1 bg-dark-bg border border-dark-border rounded px-2 py-1 text-xs font-mono text-dark-text"
              />
              <button
                class="btn-secondary text-xs px-2 py-1"
                @click=${this.handleCustomWidthSubmit}
                ?disabled=${!this.customWidth||Number.parseInt(this.customWidth)<20||Number.parseInt(this.customWidth)>500}
              >
                Set
              </button>
            </div>
          </div>
          <div class="border-t border-dark-border mt-2 pt-2">
            <div class="text-xs text-dark-text-muted mb-2 px-2">Font Size</div>
            <div class="flex items-center gap-2 px-2">
              <button
                class="btn-secondary text-xs px-2 py-1"
                @click=${()=>this.onFontSizeChange?.(this.terminalFontSize-1)}
                ?disabled=${this.terminalFontSize<=8}
              >
                −
              </button>
              <span class="font-mono text-xs text-dark-text min-w-8 text-center">
                ${this.terminalFontSize}px
              </span>
              <button
                class="btn-secondary text-xs px-2 py-1"
                @click=${()=>this.onFontSizeChange?.(this.terminalFontSize+1)}
                ?disabled=${this.terminalFontSize>=32}
              >
                +
              </button>
              <button
                class="btn-ghost text-xs px-2 py-1 ml-auto"
                @click=${()=>this.onFontSizeChange?.(14)}
                ?disabled=${this.terminalFontSize===14}
              >
                Reset
              </button>
            </div>
          </div>
        </div>
      </div>
    `:null}};_([$({type:Boolean})],$e.prototype,"visible",2),_([$({type:Number})],$e.prototype,"terminalMaxCols",2),_([$({type:Number})],$e.prototype,"terminalFontSize",2),_([$({type:String})],$e.prototype,"customWidth",2),_([$({type:Function})],$e.prototype,"onWidthSelect",2),_([$({type:Function})],$e.prototype,"onFontSizeChange",2),_([$({type:Function})],$e.prototype,"onClose",2),$e=_([z("width-selector")],$e);var oe=class extends F{constructor(){super(...arguments);this.session=null;this.showBackButton=!0;this.showSidebarToggle=!1;this.sidebarCollapsed=!1;this.terminalCols=0;this.terminalRows=0;this.terminalMaxCols=0;this.terminalFontSize=14;this.customWidth="";this.showWidthSelector=!1;this.widthLabel="";this.widthTooltip=""}createRenderRoot(){return this}getStatusText(){return this.session?"active"in this.session&&this.session.active===!1?"waiting":this.session.status:""}getStatusColor(){return!this.session||"active"in this.session&&this.session.active===!1?"text-dark-text-muted":this.session.status==="running"?"text-status-success":"text-status-warning"}getStatusDotColor(){return!this.session||"active"in this.session&&this.session.active===!1?"bg-dark-text-muted":this.session.status==="running"?"bg-status-success":"bg-status-warning"}handleCloseWidthSelector(){this.dispatchEvent(new CustomEvent("close-width-selector",{bubbles:!0,composed:!0}))}render(){return this.session?S`
      <!-- Compact Header -->
      <div
        class="flex items-center justify-between px-3 py-2 border-b border-dark-border text-sm min-w-0 bg-dark-bg-secondary"
        style="padding-top: max(0.5rem, env(safe-area-inset-top)); padding-left: max(0.75rem, env(safe-area-inset-left)); padding-right: max(0.75rem, env(safe-area-inset-right));"
      >
        <div class="flex items-center gap-3 min-w-0 flex-1">
          <!-- Mobile Hamburger Menu Button (only on phones, only when session is shown) -->
          ${this.showSidebarToggle&&this.sidebarCollapsed?S`
                <button
                  class="sm:hidden bg-dark-bg-tertiary border border-dark-border rounded-lg p-1 font-mono text-accent-green transition-all duration-300 hover:bg-dark-bg hover:border-accent-green flex-shrink-0"
                  @click=${()=>this.onSidebarToggle?.()}
                  title="Show sessions"
                >
                  <!-- Hamburger menu icon -->
                  <svg
                    width="16"
                    height="16"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                  >
                    <line x1="3" y1="6" x2="21" y2="6"></line>
                    <line x1="3" y1="12" x2="21" y2="12"></line>
                    <line x1="3" y1="18" x2="21" y2="18"></line>
                  </svg>
                </button>
              `:""}
          ${this.showBackButton?S`
                <button
                  class="btn-secondary font-mono text-xs px-3 py-1 flex-shrink-0"
                  @click=${()=>this.onBack?.()}
                >
                  Back
                </button>
              `:""}
          <div class="text-dark-text min-w-0 flex-1 overflow-hidden max-w-[50vw] sm:max-w-none">
            <div
              class="text-accent-green text-xs sm:text-sm overflow-hidden text-ellipsis whitespace-nowrap"
              title="${this.session.name||(Array.isArray(this.session.command)?this.session.command.join(" "):this.session.command)}"
            >
              ${this.session.name||(Array.isArray(this.session.command)?this.session.command.join(" "):this.session.command)}
            </div>
            <div class="text-xs opacity-75 mt-0.5 overflow-hidden">
              <clickable-path 
                .path=${this.session.workingDir} 
                .iconSize=${12}
              ></clickable-path>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-2 text-xs flex-shrink-0 ml-2 relative">
          <button
            class="btn-secondary font-mono text-xs p-1 flex-shrink-0"
            @click=${()=>this.onOpenFileBrowser?.()}
            title="Browse Files (⌘O)"
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
              <path
                d="M1.75 1h5.5c.966 0 1.75.784 1.75 1.75v1h4c.966 0 1.75.784 1.75 1.75v7.75A1.75 1.75 0 0113 15H3a1.75 1.75 0 01-1.75-1.75V2.75C1.25 1.784 1.784 1 1.75 1zM2.75 2.5v10.75c0 .138.112.25.25.25h10a.25.25 0 00.25-.25V5.5a.25.25 0 00-.25-.25H8.75v-2.5a.25.25 0 00-.25-.25h-5.5a.25.25 0 00-.25.25z"
              />
            </svg>
          </button>
          <button
            class="btn-secondary font-mono text-xs px-2 py-1 flex-shrink-0 width-selector-button"
            @click=${()=>this.onMaxWidthToggle?.()}
            title="${this.widthTooltip}"
          >
            ${this.widthLabel}
          </button>
          <width-selector
            .visible=${this.showWidthSelector}
            .terminalMaxCols=${this.terminalMaxCols}
            .terminalFontSize=${this.terminalFontSize}
            .customWidth=${this.customWidth}
            .onWidthSelect=${e=>this.onWidthSelect?.(e)}
            .onFontSizeChange=${e=>this.onFontSizeChange?.(e)}
            .onClose=${()=>this.handleCloseWidthSelector()}
          ></width-selector>
          <div class="flex flex-col items-end gap-0">
            <span class="${this.getStatusColor()} text-xs flex items-center gap-1">
              <div class="w-2 h-2 rounded-full ${this.getStatusDotColor()}"></div>
              ${this.getStatusText().toUpperCase()}
            </span>
            ${this.terminalCols>0&&this.terminalRows>0?S`
                  <span
                    class="text-dark-text-muted text-xs opacity-60"
                    style="font-size: 10px; line-height: 1;"
                  >
                    ${this.terminalCols}×${this.terminalRows}
                  </span>
                `:""}
          </div>
        </div>
      </div>
    `:null}};_([$({type:Object})],oe.prototype,"session",2),_([$({type:Boolean})],oe.prototype,"showBackButton",2),_([$({type:Boolean})],oe.prototype,"showSidebarToggle",2),_([$({type:Boolean})],oe.prototype,"sidebarCollapsed",2),_([$({type:Number})],oe.prototype,"terminalCols",2),_([$({type:Number})],oe.prototype,"terminalRows",2),_([$({type:Number})],oe.prototype,"terminalMaxCols",2),_([$({type:Number})],oe.prototype,"terminalFontSize",2),_([$({type:String})],oe.prototype,"customWidth",2),_([$({type:Boolean})],oe.prototype,"showWidthSelector",2),_([$({type:String})],oe.prototype,"widthLabel",2),_([$({type:String})],oe.prototype,"widthTooltip",2),_([$({type:Function})],oe.prototype,"onBack",2),_([$({type:Function})],oe.prototype,"onSidebarToggle",2),_([$({type:Function})],oe.prototype,"onOpenFileBrowser",2),_([$({type:Function})],oe.prototype,"onMaxWidthToggle",2),_([$({type:Function})],oe.prototype,"onWidthSelect",2),_([$({type:Function})],oe.prototype,"onFontSizeChange",2),oe=_([z("session-header")],oe);Z();Pe();Z();var _t=N("cast-converter");function at(h){let t=h.trim().split(`
`),e=null,i=[],s=[],o=0;for(let c of t)if(c.trim())try{let r=JSON.parse(c);if(r.version&&r.width&&r.height){e=r;continue}if(Array.isArray(r)&&r.length>=3){let a={timestamp:r[0],type:r[1],data:r[2]};i.push(a),a.timestamp>o&&(o=a.timestamp),a.type==="o"&&s.push(a.data)}}catch{_t.warn("failed to parse cast line")}return{header:e,content:s.join(""),events:i,totalDuration:o}}async function tn(h){let t=await fetch(h);if(!t.ok)throw new Error(`Failed to load cast file: ${t.status} ${t.statusText}`);let e=await t.text();return at(e)}function sn(h){return at(h).content}function rn(h){let t=at(h);return{cols:t.header?.width||80,rows:t.header?.height||24}}function er(h){let t=at(h),e=[],i=0;for(let s of t.events){let o=Math.max(0,(s.timestamp-i)*1e3);if(s.type==="o")e.push({delay:o,type:"output",data:s.data});else if(s.type==="r"){let c=s.data.match(/^(\d+)x(\d+)$/);c&&e.push({delay:o,type:"resize",data:s.data,cols:Number.parseInt(c[1],10),rows:Number.parseInt(c[2],10)})}i=s.timestamp}return e}async function nn(h,t,e=1){let i=er(t),s=at(t);h.setTerminalSize&&s.header&&h.setTerminalSize(s.header.width,s.header.height);for(let o of i){let c=o.delay/e;c>0&&await new Promise(r=>setTimeout(r,c)),o.type==="output"?h.write(o.data):o.type==="resize"&&h.setTerminalSize&&o.cols&&o.rows&&h.setTerminalSize(o.cols,o.rows)}}async function on(h,t){let e=at(t),i=e.header?.width||80,s=e.header?.height||24;h.setTerminalSize&&h.setTerminalSize(i,s);let o=1024*1024,c="",r=0,a=()=>{c.length>0&&(h.write(c,!1),c="",r=0)};for(let g of e.events)if(g.type==="o"){if(g.data){let m=g.data.length;r+m>o&&c.length>0&&a(),c+=g.data,r+=m}}else if(g.type==="r"){a();let m=g.data.match(/^(\d+)x(\d+)$/);if(m&&h.setTerminalSize){let l=Number.parseInt(m[1],10),v=Number.parseInt(m[2],10);h.setTerminalSize(l,v)}}a()}function an(h,t){let e=new EventSource(t),i="",s=null,o=16,c=()=>{i.length>0&&(h.write(i,!0),i=""),s=null},r=g=>{i+=g,s===null&&(s=window.setTimeout(c,o))},a=()=>{s!==null&&(clearTimeout(s),c()),e.readyState!==EventSource.CLOSED&&e.close()};return e.onmessage=g=>{try{let m=JSON.parse(g.data);if(m.version&&m.width&&m.height){h.setTerminalSize&&h.setTerminalSize(m.width,m.height);return}if(Array.isArray(m)&&m.length>=3){let[l,v,f]=m;if(l==="exit")a(),h.dispatchEvent&&h.dispatchEvent(new CustomEvent("session-exit",{detail:{exitCode:m[1],sessionId:m[2]||null},bubbles:!0}));else if(v==="o")r(f);else if(v==="r"){s!==null&&(clearTimeout(s),c());let b=f.match(/^(\d+)x(\d+)$/);if(b&&h.setTerminalSize){let w=Number.parseInt(b[1],10),n=Number.parseInt(b[2],10);h.setTerminalSize(w,n),h.dispatchEvent&&h.dispatchEvent(new CustomEvent("terminal-resize",{detail:{cols:w,rows:n},bubbles:!0}))}}else v==="i"||_t.error("unknown stream message format")}}catch(m){_t.error("failed to parse stream message:",m)}},e.onerror=g=>{_t.error("stream connection error:",g),e.readyState===EventSource.CLOSED&&_t.debug("stream connection closed")},e.onopen=()=>{_t.debug(`stream connection established to: ${t}`)},{eventSource:e,disconnect:a}}var es={convertCast:at,loadAndConvert:tn,convertToOutputOnly:sn,getTerminalDimensions:rn,convertToTimedEvents:er,playOnTerminal:nn,dumpToTerminal:on,connectToStream:an};Z();var lt=N("connection-manager"),vi=class{constructor(t,e){this.onSessionExit=t;this.onSessionUpdate=e;this.streamConnection=null;this.reconnectCount=0;this.terminal=null;this.session=null;this.isConnected=!1}setTerminal(t){this.terminal=t}setSession(t){this.session=t}setConnected(t){this.isConnected=t}connectToStream(){if(!this.terminal||!this.session){lt.warn("Cannot connect to stream - missing terminal or session");return}if(!this.isConnected){lt.warn("Component already disconnected, not connecting to stream");return}lt.log(`Connecting to stream for session ${this.session.id}`),this.cleanupStreamConnection();let t=j.getCurrentUser(),e=`/api/sessions/${this.session.id}/stream`;t?.token&&(e+=`?token=${encodeURIComponent(t.token)}`);let i=es.connectToStream(this.terminal,e),s=i.eventSource,o=0,c=3,r=5e3,a=()=>{let g=Date.now();if(g-o>r&&(this.reconnectCount=0),this.reconnectCount++,o=g,lt.log(`stream error #${this.reconnectCount} for session ${this.session?.id}`),this.reconnectCount>=c&&(lt.warn(`session ${this.session?.id} marked as exited due to excessive reconnections`),this.session&&this.session.status!=="exited")){let m={...this.session,status:"exited"};this.session=m,this.onSessionUpdate(m),this.cleanupStreamConnection(),requestAnimationFrame(()=>{this.loadSessionSnapshot()})}};s.addEventListener("error",a),this.streamConnection={...i,errorHandler:a}}cleanupStreamConnection(){this.streamConnection&&(lt.log("Cleaning up stream connection"),this.streamConnection.disconnect(),this.streamConnection=null)}getReconnectCount(){return this.reconnectCount}async loadSessionSnapshot(){if(!(!this.terminal||!this.session))try{let t=`/api/sessions/${this.session.id}/snapshot`,e=await fetch(t);if(!e.ok)throw new Error(`Failed to fetch snapshot: ${e.status}`);let i=await e.text();this.terminal.clear(),await es.dumpToTerminal(this.terminal,i),this.terminal.queueCallback(()=>{this.terminal&&this.terminal.scrollToBottom()})}catch(t){lt.error("failed to load session snapshot",t)}}};Z();var pe=N("direct-keyboard-manager"),bi=class{constructor(t){this.hiddenInput=null;this.focusRetentionInterval=null;this.inputManager=null;this.sessionViewElement=null;this.callbacks=null;this.showQuickKeys=!1;this.hiddenInputFocused=!1;this.keyboardMode=!1;this.keyboardModeTimestamp=0;this.keyboardActivationTimeout=null;this.captureClickHandler=null;this.isComposing=!1;this.compositionBuffer="";this.handleQuickKeyPress=(t,e,i)=>{if(!this.inputManager){pe.error("No input manager found");return}if(i&&t==="Done"){pe.log("Done button pressed - dismissing keyboard"),this.dismissKeyboard();return}else{if(e&&t==="Control")return;if(t==="CtrlFull"){this.callbacks&&this.callbacks.toggleCtrlAlpha(),this.callbacks?.getShowCtrlAlpha()??!1?(this.focusRetentionInterval&&(clearInterval(this.focusRetentionInterval),this.focusRetentionInterval=null),this.hiddenInput&&this.hiddenInput.blur()):(this.callbacks&&this.callbacks.clearCtrlSequence(),!(this.callbacks?.getDisableFocusManagement()??!1)&&this.hiddenInput&&this.showQuickKeys&&(this.startFocusRetention(),this.delayedRefocusHiddenInput()));return}else if(t==="Ctrl+A")this.inputManager.sendControlSequence("");else if(t==="Ctrl+C")this.inputManager.sendControlSequence("");else if(t==="Ctrl+D")this.inputManager.sendControlSequence("");else if(t==="Ctrl+E")this.inputManager.sendControlSequence("");else if(t==="Ctrl+K")this.inputManager.sendControlSequence("\v");else if(t==="Ctrl+L")this.inputManager.sendControlSequence("\f");else if(t==="Ctrl+R")this.inputManager.sendControlSequence("");else if(t==="Ctrl+U")this.inputManager.sendControlSequence("");else if(t==="Ctrl+W")this.inputManager.sendControlSequence("");else if(t==="Ctrl+Z")this.inputManager.sendControlSequence("");else if(t==="Option")this.inputManager.sendControlSequence("\x1B");else{if(t==="Command")return;if(t==="Delete")this.inputManager.sendInput("delete");else if(t.startsWith("F")){let s=Number.parseInt(t.substring(1));s>=1&&s<=12&&this.inputManager.sendInput(`f${s}`)}else{let s=t;t==="Tab"?s="tab":t==="Escape"?s="escape":t==="ArrowUp"?s="arrow_up":t==="ArrowDown"?s="arrow_down":t==="ArrowLeft"?s="arrow_left":t==="ArrowRight"?s="arrow_right":t==="PageUp"?s="page_up":t==="PageDown"?s="page_down":t==="Home"?s="home":t==="End"&&(s="end"),this.inputManager.sendInput(s.toLowerCase())}}}requestAnimationFrame(()=>{!(this.callbacks?.getDisableFocusManagement()??!1)&&this.hiddenInput&&this.showQuickKeys&&this.hiddenInput.focus()})};this.instanceId=t}setInputManager(t){this.inputManager=t}setSessionViewElement(t){this.sessionViewElement=t}setCallbacks(t){this.callbacks=t}getShowQuickKeys(){return this.showQuickKeys}setShowQuickKeys(t){this.showQuickKeys=t,t||(this.hiddenInputFocused=!1,this.focusRetentionInterval&&(clearInterval(this.focusRetentionInterval),this.focusRetentionInterval=null),this.hiddenInput&&this.hiddenInput.blur(),pe.log("Quick keys force hidden by external trigger"))}focusHiddenInput(){pe.log("Entering keyboard mode"),this.keyboardMode=!0,this.keyboardModeTimestamp=Date.now(),this.updateHiddenInputPosition(),this.captureClickHandler||(this.captureClickHandler=t=>{if(this.keyboardMode){let e=t.target;if(e.closest(".terminal-quick-keys-container")||e.closest("session-header")||e.closest("app-header")||e.closest(".modal-backdrop")||e.closest(".modal-content")||e.closest(".sidebar")||e.closest("unified-settings")||e.closest("notification-status")||e.closest("button")||e.closest("a")||e.closest('[role="button"]')||e.closest(".settings-button")||e.closest(".notification-button"))return;(e.closest("#terminal-container")||e.closest("vibe-terminal"))&&this.hiddenInput&&this.hiddenInput.focus()}},document.addEventListener("click",this.captureClickHandler,!0),document.addEventListener("pointerdown",this.captureClickHandler,!0)),this.focusRetentionInterval&&clearInterval(this.focusRetentionInterval),this.startFocusRetention(),this.ensureHiddenInputVisible()}ensureHiddenInputVisible(){this.hiddenInput||this.createHiddenInput(),this.keyboardMode&&!this.showQuickKeys&&(this.showQuickKeys=!0,this.callbacks&&(this.callbacks.updateShowQuickKeys(!0),pe.log("Showing quick keys immediately in keyboard mode"))),this.hiddenInput&&this.keyboardMode&&(this.hiddenInput.style.display="block",this.hiddenInput.style.visibility="visible",this.hiddenInput.focus(),this.hiddenInput.click(),pe.log("Focused and clicked hidden input synchronously"))}createHiddenInput(){this.hiddenInput=document.createElement("input"),this.hiddenInput.type="text",this.hiddenInput.style.position="absolute",this.hiddenInput.style.opacity="0.01",this.hiddenInput.style.fontSize="16px",this.hiddenInput.style.border="none",this.hiddenInput.style.outline="none",this.hiddenInput.style.background="transparent",this.hiddenInput.style.color="transparent",this.hiddenInput.style.caretColor="transparent",this.hiddenInput.style.cursor="default",this.hiddenInput.style.pointerEvents="none",this.hiddenInput.style.webkitUserSelect="text",this.hiddenInput.autocapitalize="off",this.hiddenInput.autocomplete="off",this.hiddenInput.setAttribute("autocorrect","off"),this.hiddenInput.setAttribute("spellcheck","false"),this.hiddenInput.setAttribute("aria-hidden","true"),this.updateHiddenInputPosition(),this.hiddenInput.addEventListener("compositionstart",()=>{this.isComposing=!0,this.compositionBuffer=""}),this.hiddenInput.addEventListener("compositionupdate",e=>{let i=e;this.compositionBuffer=i.data||""}),this.hiddenInput.addEventListener("compositionend",e=>{let i=e;this.isComposing=!1;let s=i.data||this.hiddenInput?.value||"";if(s){let o=this.callbacks?.getShowMobileInput()??!1,c=this.callbacks?.getShowCtrlAlpha()??!1;!o&&!c&&this.inputManager&&this.inputManager.sendInputText(s)}this.hiddenInput&&(this.hiddenInput.value=""),this.compositionBuffer=""}),this.hiddenInput.addEventListener("input",e=>{let i=e.target;if(!this.isComposing&&i.value){let s=this.callbacks?.getShowMobileInput()??!1,o=this.callbacks?.getShowCtrlAlpha()??!1;!s&&!o&&this.inputManager&&this.inputManager.sendInputText(i.value),i.value=""}}),this.hiddenInput.addEventListener("keydown",e=>{let i=this.callbacks?.getShowMobileInput()??!1,s=this.callbacks?.getShowCtrlAlpha()??!1;i||s||(["Enter","Backspace","Tab","Escape"].includes(e.key)&&e.preventDefault(),e.key==="Enter"&&this.inputManager?this.inputManager.sendInput("enter"):e.key==="Backspace"&&this.inputManager?this.inputManager.sendInput("backspace"):e.key==="Tab"&&this.inputManager?this.inputManager.sendInput(e.shiftKey?"shift_tab":"tab"):e.key==="Escape"&&this.inputManager&&this.inputManager.sendInput("escape"))}),this.hiddenInput.addEventListener("focus",()=>{this.hiddenInputFocused=!0,pe.log(`Hidden input focused. Keyboard mode: ${this.keyboardMode}`),this.hiddenInput&&this.keyboardMode&&(this.hiddenInput.style.pointerEvents="auto"),this.keyboardMode?(this.showQuickKeys=!0,this.callbacks&&(this.callbacks.updateShowQuickKeys(!0),pe.log("Showing quick keys due to keyboard mode")),this.hiddenInput&&this.hiddenInput.setSelectionRange(0,0)):(this.callbacks?.getKeyboardHeight()??0)>50&&(this.showQuickKeys=!0,this.callbacks&&this.callbacks.updateShowQuickKeys(!0));let e=this.callbacks?.getVisualViewportHandler();e&&e(),this.focusRetentionInterval||this.startFocusRetention()}),this.hiddenInput.addEventListener("blur",e=>{let i=e;if(pe.log(`Hidden input blurred. Keyboard mode: ${this.keyboardMode}`),pe.log(`Active element: ${document.activeElement?.tagName}, class: ${document.activeElement?.className}`),this.keyboardMode){pe.log("In keyboard mode - maintaining focus"),setTimeout(()=>{this.keyboardMode&&this.hiddenInput&&document.activeElement!==this.hiddenInput&&(pe.log("Refocusing hidden input to maintain keyboard"),this.hiddenInput.focus())},0);return}!(this.callbacks?.getDisableFocusManagement()??!1)&&this.showQuickKeys&&this.hiddenInput?setTimeout(()=>{let o=document.activeElement;!(this.sessionViewElement?.contains(o)??!1)&&o&&o!==document.body&&(this.hiddenInputFocused=!1,this.showQuickKeys=!1,this.callbacks&&this.callbacks.updateShowQuickKeys(!1),pe.log("Focus left component, hiding quick keys"),this.focusRetentionInterval&&(clearInterval(this.focusRetentionInterval),this.focusRetentionInterval=null))},100):this.hiddenInputFocused=!1});let t=this.sessionViewElement?.querySelector("#terminal-container");t&&t.appendChild(this.hiddenInput)}startFocusRetention(){this.focusRetentionInterval=setInterval(()=>{let t=this.callbacks?.getDisableFocusManagement()??!1,e=this.callbacks?.getShowMobileInput()??!1,i=this.callbacks?.getShowCtrlAlpha()??!1;if(this.keyboardMode&&this.hiddenInput&&document.activeElement!==this.hiddenInput){pe.log("Keyboard mode: forcing focus on hidden input"),this.hiddenInput.focus();return}!t&&this.showQuickKeys&&this.hiddenInput&&document.activeElement!==this.hiddenInput&&!e&&!i&&(pe.log("Refocusing hidden input to maintain keyboard"),this.hiddenInput.focus())},100)}delayedRefocusHiddenInput(){setTimeout(()=>{!(this.callbacks?.getDisableFocusManagement()??!1)&&this.hiddenInput&&this.hiddenInput.focus()},100)}shouldRefocusHiddenInput(){return!(this.callbacks?.getDisableFocusManagement()??!1)&&!!this.hiddenInput&&this.showQuickKeys}refocusHiddenInput(){setTimeout(()=>{!(this.callbacks?.getDisableFocusManagement()??!1)&&this.hiddenInput&&this.hiddenInput.focus()},100)}startFocusRetentionPublic(){this.startFocusRetention()}delayedRefocusHiddenInputPublic(){this.delayedRefocusHiddenInput()}updateHiddenInputPosition(){this.hiddenInput&&(this.keyboardMode?(this.hiddenInput.style.position="absolute",this.hiddenInput.style.top="0",this.hiddenInput.style.left="0",this.hiddenInput.style.width="100%",this.hiddenInput.style.height="1px",this.hiddenInput.style.zIndex="10",this.hiddenInput.style.pointerEvents="none"):(this.hiddenInput.style.position="fixed",this.hiddenInput.style.left="-9999px",this.hiddenInput.style.top="-9999px",this.hiddenInput.style.width="1px",this.hiddenInput.style.height="1px",this.hiddenInput.style.zIndex="-1",this.hiddenInput.style.pointerEvents="none"))}dismissKeyboard(){this.keyboardMode=!1,this.keyboardModeTimestamp=0,this.captureClickHandler&&(document.removeEventListener("click",this.captureClickHandler,!0),document.removeEventListener("pointerdown",this.captureClickHandler,!0),this.captureClickHandler=null),this.showQuickKeys=!1,this.callbacks&&(this.callbacks.updateShowQuickKeys(!1),this.callbacks.setKeyboardHeight(0)),this.focusRetentionInterval&&(clearInterval(this.focusRetentionInterval),this.focusRetentionInterval=null),this.keyboardActivationTimeout&&(clearTimeout(this.keyboardActivationTimeout),this.keyboardActivationTimeout=null),this.hiddenInput&&(this.hiddenInput.blur(),this.hiddenInputFocused=!1,this.updateHiddenInputPosition()),pe.log("Keyboard dismissed")}cleanup(){this.focusRetentionInterval&&(clearInterval(this.focusRetentionInterval),this.focusRetentionInterval=null),this.keyboardActivationTimeout&&(clearTimeout(this.keyboardActivationTimeout),this.keyboardActivationTimeout=null),this.captureClickHandler&&(document.removeEventListener("click",this.captureClickHandler,!0),document.removeEventListener("pointerdown",this.captureClickHandler,!0),this.captureClickHandler=null),this.hiddenInput&&(this.hiddenInput.remove(),this.hiddenInput=null)}};Pe();Z();var ye=N("websocket-input-client"),ts=class{constructor(){this.ws=null;this.session=null;this.reconnectTimeout=null;this.connectionPromise=null;this.isConnecting=!1;this.RECONNECT_DELAY=1e3;this.MAX_RECONNECT_DELAY=5e3;this.cleanup=this.cleanup.bind(this),window.addEventListener("beforeunload",this.cleanup)}async connect(t){if(this.session?.id===t.id&&this.ws?.readyState===WebSocket.OPEN){ye.debug(`Already connected to session ${t.id}`);return}if(this.session?.id!==t.id&&(ye.debug(`Switching from session ${this.session?.id} to ${t.id}`),this.disconnect()),this.session=t,ye.debug(`Connecting to WebSocket for session ${t.id}`),this.connectionPromise)return this.connectionPromise;this.connectionPromise=this.establishConnection();try{await this.connectionPromise}finally{this.connectionPromise=null}}async establishConnection(){if(!this.session)throw new Error("No session provided");this.isConnecting=!0;let t=window.location.protocol==="https:"?"wss:":"ws:",e=window.location.host,i=this.session.id,s=localStorage.getItem("vibetunnel_auth_token")||localStorage.getItem("auth_token")||`dev-token-${Date.now()}`,o=`${t}//${e}/ws/input?sessionId=${i}&token=${encodeURIComponent(s)}`;try{ye.log(`Connecting to WebSocket: ${o}`),this.ws=new WebSocket(o),this.ws.onopen=()=>{ye.log("WebSocket connected successfully"),this.isConnecting=!1},this.ws.onclose=c=>{ye.log(`WebSocket closed: code=${c.code}, reason=${c.reason}`),this.isConnecting=!1,this.ws=null,this.scheduleReconnect()},this.ws.onerror=c=>{ye.error("WebSocket error:",c),this.isConnecting=!1},await new Promise((c,r)=>{let a=setTimeout(()=>{r(new Error("WebSocket connection timeout"))},5e3);this.ws?.addEventListener("open",()=>{clearTimeout(a),c()}),this.ws?.addEventListener("error",()=>{clearTimeout(a),r(new Error("WebSocket connection failed"))})})}catch(c){throw ye.error("Failed to establish WebSocket connection:",c),this.isConnecting=!1,c}}sendInput(t){if(!this.session||!this.ws||this.ws.readyState!==WebSocket.OPEN)return!1;try{let e;if(t.key)e=`\0${t.key}\0`,ye.debug(`Sending special key: "${t.key}" as: ${JSON.stringify(e)}`);else if(t.text)e=t.text,ye.debug(`Sending text: ${JSON.stringify(e)}`);else return!1;return this.ws.send(e),ye.debug("Sent raw input via WebSocket:",JSON.stringify(e)),!0}catch(e){return ye.error("Failed to send via WebSocket:",e),!1}}scheduleReconnect(){if(this.reconnectTimeout)return;let t=Math.min(this.RECONNECT_DELAY*2,this.MAX_RECONNECT_DELAY);ye.log(`Scheduling reconnect in ${t}ms`),this.reconnectTimeout=setTimeout(()=>{this.reconnectTimeout=null,this.session&&this.connect(this.session).catch(e=>{ye.error("Reconnection failed:",e)})},t)}isConnected(){return this.ws?.readyState===WebSocket.OPEN}disconnect(){this.reconnectTimeout&&(clearTimeout(this.reconnectTimeout),this.reconnectTimeout=null),this.ws&&(this.ws.close(),this.ws=null),this.session=null,this.isConnecting=!1}cleanup(){this.disconnect(),window.removeEventListener("beforeunload",this.cleanup)}},yi=new ts;Z();var ct=N("input-manager"),wi=class{constructor(){this.session=null;this.callbacks=null;this.useWebSocketInput=!0}setSession(t){this.session=t;let i=new URLSearchParams(window.location.search).get("socket_input");i!==null&&(this.useWebSocketInput=i==="true",ct.log(`WebSocket input ${this.useWebSocketInput?"enabled":"disabled"} via URL parameter`)),t&&this.useWebSocketInput&&yi.connect(t).catch(s=>{ct.debug("WebSocket connection failed, will use HTTP fallback:",s)})}setCallbacks(t){this.callbacks=t}async handleKeyboardInput(t){if(!this.session||t.key==="Escape"&&this.session.status==="exited")return;if(this.session.status==="exited"){ct.log("ignoring keyboard input - session has exited");return}let e=navigator.platform.toLowerCase().includes("mac"),i=e&&t.metaKey&&t.key==="v"&&!t.ctrlKey&&!t.shiftKey||!e&&t.ctrlKey&&t.key==="v"&&!t.shiftKey,s=e&&t.metaKey&&t.key==="c"&&!t.ctrlKey&&!t.shiftKey||!e&&t.ctrlKey&&t.key==="c"&&!t.shiftKey;if(i||s)return;let o="";switch(t.key){case"Enter":t.ctrlKey?o="ctrl_enter":t.shiftKey?o="shift_enter":o="enter";break;case"Escape":o="escape";break;case"ArrowUp":o="arrow_up";break;case"ArrowDown":o="arrow_down";break;case"ArrowLeft":o="arrow_left";break;case"ArrowRight":o="arrow_right";break;case"Tab":o=t.shiftKey?"shift_tab":"tab";break;case"Backspace":o="backspace";break;case"Delete":o="delete";break;case" ":o=" ";break;default:if(t.key.length===1)o=t.key;else return;break}if(t.ctrlKey&&t.key.length===1&&t.key!=="Enter"){let c=t.key.toLowerCase().charCodeAt(0);c>=97&&c<=122&&(o=String.fromCharCode(c-96))}await this.sendInput(o)}async sendInputInternal(t,e){if(this.session)try{if(this.useWebSocketInput&&yi.sendInput(t))return;ct.debug("WebSocket unavailable, falling back to HTTP");let i=await fetch(`/api/sessions/${this.session.id}/input`,{method:"POST",headers:{"Content-Type":"application/json",...j.getAuthHeader()},body:JSON.stringify(t)});i.ok||(i.status===400?(ct.log("session no longer accepting input (likely exited)"),this.session&&(this.session.status="exited",this.callbacks&&this.callbacks.requestUpdate())):ct.error(`failed to ${e}`,{status:i.status}))}catch(i){ct.error(`error ${e}`,i)}}async sendInputText(t){await this.sendInputInternal({text:t},"send input to session")}async sendControlSequence(t){await this.sendInputInternal({text:t},"send control sequence to session")}async sendInput(t){let i=["enter","escape","backspace","tab","shift_tab","arrow_up","arrow_down","arrow_left","arrow_right","ctrl_enter","shift_enter","page_up","page_down","home","end","delete","f1","f2","f3","f4","f5","f6","f7","f8","f9","f10","f11","f12"].includes(t)?{key:t}:{text:t};await this.sendInputInternal(i,"send input to session")}isKeyboardShortcut(t){let e=t.target;if(e.tagName==="INPUT"||e.tagName==="TEXTAREA"||e.tagName==="SELECT"||e.contentEditable==="true"||e.closest(".monaco-editor")||e.closest("[data-keybinding-context]")||e.closest(".editor-container"))return!1;let i=navigator.platform.toLowerCase().includes("mac");return!!(t.key==="F12"||!i&&t.ctrlKey&&t.shiftKey&&t.key==="I"||i&&t.metaKey&&t.altKey&&t.key==="I"||!i&&t.ctrlKey&&!t.shiftKey&&["a","f","r","l","t","w","n","c","v"].includes(t.key.toLowerCase())||i&&t.metaKey&&!t.shiftKey&&!t.altKey&&["a","f","r","l","t","w","n","c","v"].includes(t.key.toLowerCase())||(t.altKey||t.metaKey)&&t.key==="Tab")}cleanup(){this.useWebSocketInput&&yi.disconnect(),this.session=null,this.callbacks=null}};Z();var _i=class extends EventTarget{emit(t,e){this.dispatchEvent(new CustomEvent(t,{detail:e}))}on(t,e){this.addEventListener(t,e)}off(t,e){this.removeEventListener(t,e)}};var Be=N("lifecycle-event-manager"),xi=class extends _i{constructor(){super();this.sessionViewElement=null;this.callbacks=null;this.session=null;this.touchStartX=0;this.touchStartY=0;this.keyboardListenerAdded=!1;this.touchListenersAdded=!1;this.visualViewportHandler=null;this.clickHandler=null;this.handlePreferencesChanged=e=>{if(!this.callbacks)return;let s=e.detail;this.callbacks.setUseDirectKeyboard(s.useDirectKeyboard);let o=this.callbacks.getIsMobile(),c=this.callbacks.getUseDirectKeyboard(),r=this.callbacks.getDirectKeyboardManager();o&&c&&!r.getShowQuickKeys()?r.ensureHiddenInputVisible():c||(r.cleanup(),this.callbacks.setShowQuickKeys(!1))};this.keyboardHandler=e=>{if(!this.callbacks)return;if((e.metaKey||e.ctrlKey)&&e.key==="o"){e.preventDefault(),this.callbacks.setShowFileBrowser(!0);return}if(!(!this.session||this.callbacks.getInputManager()?.isKeyboardShortcut(e))){if(e.key==="Escape"&&this.session.status==="exited"){this.callbacks.handleBack();return}e.preventDefault(),e.stopPropagation(),this.callbacks.handleKeyboardInput(e)}};this.touchStartHandler=e=>{if(!this.callbacks||!this.callbacks.getIsMobile())return;let s=e.touches[0];this.touchStartX=s.clientX,this.touchStartY=s.clientY};this.touchEndHandler=e=>{if(!this.callbacks||!this.callbacks.getIsMobile())return;let s=e.changedTouches[0],o=s.clientX,c=s.clientY,r=o-this.touchStartX,a=c-this.touchStartY,g=r>100,m=Math.abs(a)<100,l=this.touchStartX<50;g&&m&&l&&this.callbacks.handleBack()};this.handleClickOutside=e=>{if(!this.callbacks)return;if(this.callbacks.getShowWidthSelector()){let s=e.target,o=this.callbacks.querySelector(".width-selector-container"),c=this.callbacks.querySelector(".width-selector-button");!o?.contains(s)&&!c?.contains(s)&&(this.callbacks.setShowWidthSelector(!1),this.callbacks.setCustomWidth(""))}};Be.log("LifecycleEventManager initialized")}setSessionViewElement(e){this.sessionViewElement=e}setCallbacks(e){this.callbacks=e}setSession(e){this.session=e}setupLifecycle(){if(!this.callbacks)return;this.callbacks.setTabIndex(0),this.clickHandler=()=>{this.callbacks?.getDisableFocusManagement()||this.callbacks?.focus()},this.callbacks.addEventListener("click",this.clickHandler),document.addEventListener("click",this.handleClickOutside),this.session||this.callbacks.startLoading();let e=/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);this.callbacks.setIsMobile(e),window.addEventListener("app-preferences-changed",this.handlePreferencesChanged),this.setupMobileFeatures(e),this.setupEventListeners(e)}setupMobileFeatures(e){if(this.callbacks){if(e&&"virtualKeyboard"in navigator)try{let i=navigator;i.virtualKeyboard&&(i.virtualKeyboard.overlaysContent=!0),Be.log("VirtualKeyboard API: overlaysContent enabled")}catch(i){Be.warn("Failed to set virtualKeyboard.overlaysContent:",i)}else e&&Be.log("VirtualKeyboard API not available on this device");if(e&&window.visualViewport){let i=0;this.visualViewportHandler=()=>{let s=window.visualViewport;if(!s||!this.callbacks)return;let o=window.innerHeight-s.height;this.callbacks.setKeyboardHeight(o);let c=this.callbacks.querySelector("terminal-quick-keys");if(c&&(c.keyboardHeight=o),Be.log(`Visual Viewport keyboard height: ${o}px`),i>50&&o<50){Be.log("Keyboard dismissed detected via viewport change");let r=this.callbacks.getUseDirectKeyboard(),a=this.callbacks.getDirectKeyboardManager();r&&a&&a.getShowQuickKeys()&&(this.callbacks.setShowQuickKeys(!1),a.setShowQuickKeys&&a.setShowQuickKeys(!1),Be.log("Force hiding quick keys after keyboard dismissal"))}i=o},window.visualViewport.addEventListener("resize",this.visualViewportHandler),window.visualViewport.addEventListener("scroll",this.visualViewportHandler)}}}setupEventListeners(e){!e&&!this.keyboardListenerAdded?(document.addEventListener("keydown",this.keyboardHandler),this.keyboardListenerAdded=!0):e&&!this.touchListenersAdded&&(document.addEventListener("touchstart",this.touchStartHandler,{passive:!0}),document.addEventListener("touchend",this.touchEndHandler,{passive:!0}),this.touchListenersAdded=!0)}teardownLifecycle(){if(!this.callbacks)return;Be.log("SessionView disconnectedCallback called",{sessionId:this.session?.id,sessionStatus:this.session?.status}),this.callbacks.setConnected(!1);let e=this.callbacks.getTerminalLifecycleManager();this.session&&this.session.status!=="exited"&&e&&(Be.log("Calling resetTerminalSize for session",this.session.id),e.resetTerminalSize());let i=this.callbacks.getConnectionManager();i&&i.setConnected(!1),e&&e.cleanup(),document.removeEventListener("click",this.handleClickOutside),this.clickHandler&&(this.callbacks.removeEventListener("click",this.clickHandler),this.clickHandler=null),!this.callbacks.getIsMobile()&&this.keyboardListenerAdded?(document.removeEventListener("keydown",this.keyboardHandler),this.keyboardListenerAdded=!1):this.callbacks.getIsMobile()&&this.touchListenersAdded&&(document.removeEventListener("touchstart",this.touchStartHandler),document.removeEventListener("touchend",this.touchEndHandler),this.touchListenersAdded=!1);let s=this.callbacks.getDirectKeyboardManager();s&&s.cleanup(),this.visualViewportHandler&&window.visualViewport&&(window.visualViewport.removeEventListener("resize",this.visualViewportHandler),window.visualViewport.removeEventListener("scroll",this.visualViewportHandler),this.visualViewportHandler=null),window.removeEventListener("app-preferences-changed",this.handlePreferencesChanged),this.callbacks.stopLoading(),i&&i.cleanupStreamConnection()}cleanup(){Be.log("LifecycleEventManager cleanup"),document.removeEventListener("click",this.handleClickOutside),window.removeEventListener("app-preferences-changed",this.handlePreferencesChanged),!this.callbacks?.getIsMobile()&&this.keyboardListenerAdded?(document.removeEventListener("keydown",this.keyboardHandler),this.keyboardListenerAdded=!1):this.callbacks?.getIsMobile()&&this.touchListenersAdded&&(document.removeEventListener("touchstart",this.touchStartHandler),document.removeEventListener("touchend",this.touchEndHandler),this.touchListenersAdded=!1),this.visualViewportHandler&&window.visualViewport&&(window.visualViewport.removeEventListener("resize",this.visualViewportHandler),window.visualViewport.removeEventListener("scroll",this.visualViewportHandler),this.visualViewportHandler=null),this.clickHandler=null,this.sessionViewElement=null,this.callbacks=null,this.session=null}};var Si=class{constructor(){this.loading=!1;this.loadingFrame=0;this.loadingInterval=null}isLoading(){return this.loading}getLoadingFrame(){return this.loadingFrame}startLoading(t){this.loading=!0,this.loadingFrame=0,this.loadingInterval=window.setInterval(()=>{this.loadingFrame=(this.loadingFrame+1)%4,t&&t()},200)}stopLoading(){this.loading=!1,this.loadingInterval&&(clearInterval(this.loadingInterval),this.loadingInterval=null)}getLoadingText(){let t=["\u280B","\u2819","\u2839","\u2838","\u283C","\u2834","\u2826","\u2827","\u2807","\u280F"];return t[this.loadingFrame%t.length]}cleanup(){this.loadingInterval&&(clearInterval(this.loadingInterval),this.loadingInterval=null)}};var ki=class{constructor(t){this.inputManager=null;this.terminal=null;this.sessionView=t}setInputManager(t){this.inputManager=t}setTerminal(t){this.terminal=t}handleMobileInputToggle(){if(this.sessionView.shouldUseDirectKeyboard()){this.sessionView.focusHiddenInput();return}this.sessionView.toggleMobileInputDisplay()}async handleMobileInputSendOnly(t){let e=t?.trim();if(e)try{this.inputManager&&await this.inputManager.sendInputText(e),this.sessionView.clearMobileInputText(),this.sessionView.requestUpdate(),this.sessionView.closeMobileInput(),this.sessionView.shouldRefocusHiddenInput()&&this.sessionView.refocusHiddenInput(),this.sessionView.refreshTerminalAfterMobileInput()}catch(i){console.error("error sending mobile input",i)}}async handleMobileInputSend(t){let e=t?.trim();if(e)try{this.inputManager&&(await this.inputManager.sendInputText(e),await this.inputManager.sendInput("enter")),this.sessionView.clearMobileInputText(),this.sessionView.requestUpdate(),this.sessionView.closeMobileInput(),this.sessionView.shouldRefocusHiddenInput()&&this.sessionView.refocusHiddenInput(),this.sessionView.refreshTerminalAfterMobileInput()}catch(i){console.error("error sending mobile input",i)}}handleMobileInputCancel(){this.sessionView.closeMobileInput(),this.sessionView.clearMobileInputText(),this.sessionView.shouldRefocusHiddenInput()&&(this.sessionView.startFocusRetention(),this.sessionView.delayedRefocusHiddenInput())}cleanup(){this.inputManager=null}};Pe();Z();var Te=N("terminal-lifecycle-manager"),Ci=class{constructor(){this.session=null;this.terminal=null;this.connectionManager=null;this.inputManager=null;this.connected=!1;this.terminalFontSize=14;this.terminalMaxCols=0;this.resizeTimeout=null;this.lastResizeWidth=0;this.lastResizeHeight=0;this.domElement=null;this.eventHandlers=null;this.stateCallbacks=null}setSession(t){this.session=t}setTerminal(t){this.terminal=t}setConnectionManager(t){this.connectionManager=t}setInputManager(t){this.inputManager=t}setConnected(t){this.connected=t}setTerminalFontSize(t){this.terminalFontSize=t}setTerminalMaxCols(t){this.terminalMaxCols=t}getTerminal(){return this.terminal}setDomElement(t){this.domElement=t}setEventHandlers(t){this.eventHandlers=t}setStateCallbacks(t){this.stateCallbacks=t}setupTerminal(){}async initializeTerminal(){if(!this.domElement){Te.warn("Cannot initialize terminal - missing DOM element");return}let t=this.domElement.querySelector("vibe-terminal");if(!t||!this.session){Te.warn("Cannot initialize terminal - missing element or session");return}this.terminal=t,this.connectionManager&&(this.connectionManager.setTerminal(this.terminal),this.connectionManager.setSession(this.session)),this.terminal.cols=80,this.terminal.rows=24,this.terminal.fontSize=this.terminalFontSize,this.terminal.fitHorizontally=!1,this.terminal.maxCols=this.terminalMaxCols,this.eventHandlers&&(this.terminal.addEventListener("session-exit",this.eventHandlers.handleSessionExit),this.terminal.addEventListener("terminal-resize",this.eventHandlers.handleTerminalResize),this.terminal.addEventListener("terminal-paste",this.eventHandlers.handleTerminalPaste)),setTimeout(()=>{this.connected&&this.connectionManager?this.connectionManager.connectToStream():Te.warn("Component disconnected before stream connection")},0)}async handleTerminalResize(t){let e=t,{cols:i,rows:s}=e.detail;this.stateCallbacks&&this.stateCallbacks.updateTerminalDimensions(i,s),this.resizeTimeout&&clearTimeout(this.resizeTimeout),this.resizeTimeout=window.setTimeout(async()=>{if(i===this.lastResizeWidth&&s===this.lastResizeHeight){Te.debug(`skipping redundant resize request: ${i}x${s}`);return}if(this.session&&this.session.status!=="exited")try{Te.debug(`sending resize request: ${i}x${s} (was ${this.lastResizeWidth}x${this.lastResizeHeight})`);let o=await fetch(`/api/sessions/${this.session.id}/resize`,{method:"POST",headers:{"Content-Type":"application/json",...j.getAuthHeader()},body:JSON.stringify({cols:i,rows:s})});o.ok?(this.lastResizeWidth=i,this.lastResizeHeight=s):Te.warn(`failed to resize session: ${o.status}`)}catch(o){Te.warn("failed to send resize request",o)}},250)}handleTerminalPaste(t){let i=t.detail?.text;i&&this.session&&this.inputManager&&this.inputManager.sendInputText(i)}async resetTerminalSize(){if(!this.session){Te.warn("resetTerminalSize called but no session available");return}Te.log("Sending reset-size request for session",this.session.id);try{let t=await fetch(`/api/sessions/${this.session.id}/reset-size`,{method:"POST",headers:{"Content-Type":"application/json",...j.getAuthHeader()}});t.ok?Te.log("terminal size reset successfully for session",this.session.id):Te.error("failed to reset terminal size",{status:t.status,sessionId:this.session.id})}catch(t){Te.error("error resetting terminal size",{error:t,sessionId:this.session.id})}}cleanup(){this.resizeTimeout&&(clearTimeout(this.resizeTimeout),this.resizeTimeout=null)}};var Ge=N("session-view"),Q=class extends F{constructor(){super(...arguments);this.session=null;this.showBackButton=!0;this.showSidebarToggle=!1;this.sidebarCollapsed=!1;this.disableFocusManagement=!1;this.connected=!1;this.showMobileInput=!1;this.mobileInputText="";this.isMobile=!1;this.touchStartX=0;this.touchStartY=0;this.terminalCols=0;this.terminalRows=0;this.showCtrlAlpha=!1;this.terminalFitHorizontally=!1;this.terminalMaxCols=0;this.showWidthSelector=!1;this.customWidth="";this.showFileBrowser=!1;this.terminalFontSize=14;this.terminalContainerHeight="100%";this.preferencesManager=gi.getInstance();this.loadingAnimationManager=new Si;this.ctrlSequence=[];this.useDirectKeyboard=!1;this.showQuickKeys=!1;this.keyboardHeight=0;this.instanceId=`session-view-${Math.random().toString(36).substr(2,9)}`;this.createHiddenInputTimeout=null}createRenderRoot(){return this}createLifecycleEventManagerCallbacks(){return{requestUpdate:()=>this.requestUpdate(),handleBack:()=>this.handleBack(),handleKeyboardInput:e=>this.handleKeyboardInput(e),getIsMobile:()=>this.isMobile,setIsMobile:e=>{this.isMobile=e},getUseDirectKeyboard:()=>this.useDirectKeyboard,setUseDirectKeyboard:e=>{this.useDirectKeyboard=e},getDirectKeyboardManager:()=>({getShowQuickKeys:()=>this.directKeyboardManager.getShowQuickKeys(),setShowQuickKeys:e=>this.directKeyboardManager.setShowQuickKeys(e),ensureHiddenInputVisible:()=>this.directKeyboardManager.ensureHiddenInputVisible(),cleanup:()=>this.directKeyboardManager.cleanup()}),setShowQuickKeys:e=>{this.showQuickKeys=e,this.updateTerminalTransform()},setShowFileBrowser:e=>{this.showFileBrowser=e},getInputManager:()=>this.inputManager,getShowWidthSelector:()=>this.showWidthSelector,setShowWidthSelector:e=>{this.showWidthSelector=e},setCustomWidth:e=>{this.customWidth=e},querySelector:e=>this.querySelector(e),setTabIndex:e=>{this.tabIndex=e},addEventListener:(e,i)=>this.addEventListener(e,i),removeEventListener:(e,i)=>this.removeEventListener(e,i),focus:()=>this.focus(),getDisableFocusManagement:()=>this.disableFocusManagement,startLoading:()=>this.loadingAnimationManager.startLoading(()=>this.requestUpdate()),stopLoading:()=>this.loadingAnimationManager.stopLoading(),setKeyboardHeight:e=>{this.keyboardHeight=e,this.updateTerminalTransform()},getTerminalLifecycleManager:()=>this.terminalLifecycleManager?{resetTerminalSize:()=>this.terminalLifecycleManager.resetTerminalSize(),cleanup:()=>this.terminalLifecycleManager.cleanup()}:null,getConnectionManager:()=>this.connectionManager?{setConnected:e=>this.connectionManager.setConnected(e),cleanupStreamConnection:()=>this.connectionManager.cleanupStreamConnection()}:null,setConnected:e=>{this.connected=e}}}connectedCallback(){super.connectedCallback(),this.connected=!0,this.connectionManager=new vi(o=>{this.session&&o===this.session.id&&(this.session={...this.session,status:"exited"},this.requestUpdate())},o=>{this.session=o,this.requestUpdate()}),this.connectionManager.setConnected(!0),this.inputManager=new wi,this.inputManager.setCallbacks({requestUpdate:()=>this.requestUpdate()}),this.mobileInputManager=new ki(this),this.mobileInputManager.setInputManager(this.inputManager),this.directKeyboardManager=new bi(this.instanceId),this.directKeyboardManager.setInputManager(this.inputManager),this.directKeyboardManager.setSessionViewElement(this);let e={getShowMobileInput:()=>this.showMobileInput,getShowCtrlAlpha:()=>this.showCtrlAlpha,getDisableFocusManagement:()=>this.disableFocusManagement,getVisualViewportHandler:()=>{if(this.lifecycleEventManager&&window.visualViewport){let o=window.visualViewport,c=window.innerHeight-o.height;this.keyboardHeight=c;let r=this.querySelector("terminal-quick-keys");return r&&(r.keyboardHeight=c),Ge.log(`Visual Viewport keyboard height (manual trigger): ${c}px`),()=>{if(window.visualViewport){let a=window.innerHeight-window.visualViewport.height;this.keyboardHeight=a,r&&(r.keyboardHeight=a)}}}return null},getKeyboardHeight:()=>this.keyboardHeight,setKeyboardHeight:o=>{this.keyboardHeight=o,this.updateTerminalTransform(),this.requestUpdate()},updateShowQuickKeys:o=>{this.showQuickKeys=o,this.requestUpdate(),this.updateTerminalTransform()},toggleMobileInput:()=>{this.showMobileInput=!this.showMobileInput,this.requestUpdate()},clearMobileInputText:()=>{this.mobileInputText="",this.requestUpdate()},toggleCtrlAlpha:()=>{this.showCtrlAlpha=!this.showCtrlAlpha,this.requestUpdate()},clearCtrlSequence:()=>{this.ctrlSequence=[],this.requestUpdate()}};this.directKeyboardManager.setCallbacks(e),this.terminalLifecycleManager=new Ci,this.terminalLifecycleManager.setConnectionManager(this.connectionManager),this.terminalLifecycleManager.setInputManager(this.inputManager),this.terminalLifecycleManager.setConnected(this.connected),this.terminalLifecycleManager.setDomElement(this);let i={handleSessionExit:this.handleSessionExit.bind(this),handleTerminalResize:this.terminalLifecycleManager.handleTerminalResize.bind(this.terminalLifecycleManager),handleTerminalPaste:this.terminalLifecycleManager.handleTerminalPaste.bind(this.terminalLifecycleManager)};this.terminalLifecycleManager.setEventHandlers(i);let s={updateTerminalDimensions:(o,c)=>{this.terminalCols=o,this.terminalRows=c,this.requestUpdate()}};this.terminalLifecycleManager.setStateCallbacks(s),this.session&&(this.inputManager.setSession(this.session),this.terminalLifecycleManager.setSession(this.session)),this.terminalMaxCols=this.preferencesManager.getMaxCols(),this.terminalFontSize=this.preferencesManager.getFontSize(),this.terminalLifecycleManager.setTerminalFontSize(this.terminalFontSize),this.terminalLifecycleManager.setTerminalMaxCols(this.terminalMaxCols),this.lifecycleEventManager=new xi,this.lifecycleEventManager.setSessionViewElement(this),this.lifecycleEventManager.setCallbacks(this.createLifecycleEventManagerCallbacks()),this.lifecycleEventManager.setSession(this.session);try{let o=localStorage.getItem("vibetunnel_app_preferences");if(o){let c=JSON.parse(o);this.useDirectKeyboard=c.useDirectKeyboard??!0}else this.useDirectKeyboard=!0}catch(o){Ge.error("Failed to load app preferences",o),this.useDirectKeyboard=!0}this.lifecycleEventManager.setupLifecycle()}disconnectedCallback(){super.disconnectedCallback(),this.createHiddenInputTimeout&&(clearTimeout(this.createHiddenInputTimeout),this.createHiddenInputTimeout=null),this.lifecycleEventManager&&(this.lifecycleEventManager.teardownLifecycle(),this.lifecycleEventManager.cleanup()),this.loadingAnimationManager.cleanup()}firstUpdated(e){super.firstUpdated(e),this.session&&this.connected&&this.terminalLifecycleManager.setupTerminal()}updated(e){if(super.updated(e),e.has("session")){let i=e.get("session");i&&i.id!==this.session?.id&&(Ge.log("Session changed, cleaning up old stream connection"),this.connectionManager&&this.connectionManager.cleanupStreamConnection()),this.inputManager&&this.inputManager.setSession(this.session),this.terminalLifecycleManager&&this.terminalLifecycleManager.setSession(this.session),this.lifecycleEventManager&&this.lifecycleEventManager.setSession(this.session)}if(e.has("session")&&this.session&&this.loadingAnimationManager.isLoading()&&(this.loadingAnimationManager.stopLoading(),this.terminalLifecycleManager.setupTerminal()),!this.terminalLifecycleManager.getTerminal()&&this.session&&this.connected&&this.querySelector("vibe-terminal")&&this.terminalLifecycleManager.initializeTerminal(),this.isMobile&&this.useDirectKeyboard&&!this.directKeyboardManager.getShowQuickKeys()&&this.session&&this.connected){this.createHiddenInputTimeout&&clearTimeout(this.createHiddenInputTimeout);let i=100;this.createHiddenInputTimeout=setTimeout(()=>{try{this.isMobile&&this.useDirectKeyboard&&!this.directKeyboardManager.getShowQuickKeys()&&this.connected&&this.directKeyboardManager.ensureHiddenInputVisible()}catch(s){Ge.warn("Failed to create hidden input during setTimeout:",s)}this.createHiddenInputTimeout=null},i)}}async handleKeyboardInput(e){this.inputManager&&(await this.inputManager.handleKeyboardInput(e),this.session&&this.session.status)}handleBack(){this.dispatchEvent(new CustomEvent("navigate-to-list",{bubbles:!0,composed:!0}))}handleSidebarToggle(){this.dispatchEvent(new CustomEvent("toggle-sidebar",{bubbles:!0,composed:!0}))}handleSessionExit(e){let i=e;Ge.log("session exit event received",i.detail),this.session&&i.detail.sessionId===this.session.id&&(this.session={...this.session,status:"exited"},this.requestUpdate(),this.connectionManager&&this.connectionManager.cleanupStreamConnection(),this.dispatchEvent(new CustomEvent("session-status-changed",{detail:{sessionId:this.session.id,newStatus:"exited",exitCode:i.detail.exitCode},bubbles:!0})))}handleMobileInputToggle(){this.mobileInputManager.handleMobileInputToggle()}shouldUseDirectKeyboard(){return this.useDirectKeyboard}toggleMobileInputDisplay(){this.showMobileInput=!this.showMobileInput,this.showMobileInput||this.refreshTerminalAfterMobileInput()}getMobileInputText(){return this.mobileInputText}clearMobileInputText(){this.mobileInputText=""}closeMobileInput(){this.showMobileInput=!1}shouldRefocusHiddenInput(){return this.directKeyboardManager.shouldRefocusHiddenInput()}refocusHiddenInput(){this.directKeyboardManager.refocusHiddenInput()}startFocusRetention(){this.directKeyboardManager.startFocusRetentionPublic()}delayedRefocusHiddenInput(){this.directKeyboardManager.delayedRefocusHiddenInputPublic()}async handleMobileInputSendOnly(e){await this.mobileInputManager.handleMobileInputSendOnly(e)}async handleMobileInputSend(e){await this.mobileInputManager.handleMobileInputSend(e)}handleMobileInputCancel(){this.mobileInputManager.handleMobileInputCancel()}async handleSpecialKey(e){this.inputManager&&await this.inputManager.sendInputText(e)}handleCtrlAlphaToggle(){this.showCtrlAlpha=!this.showCtrlAlpha}async handleCtrlKey(e){this.ctrlSequence=[...this.ctrlSequence,e],this.requestUpdate()}async handleSendCtrlSequence(){if(this.inputManager)for(let e of this.ctrlSequence){let i=String.fromCharCode(e.charCodeAt(0)-64);await this.inputManager.sendInputText(i)}this.ctrlSequence=[],this.showCtrlAlpha=!1,this.requestUpdate(),this.directKeyboardManager.shouldRefocusHiddenInput()&&this.directKeyboardManager.refocusHiddenInput()}handleClearCtrlSequence(){this.ctrlSequence=[],this.requestUpdate()}handleCtrlAlphaCancel(){this.showCtrlAlpha=!1,this.ctrlSequence=[],this.requestUpdate(),this.directKeyboardManager.shouldRefocusHiddenInput()&&this.directKeyboardManager.refocusHiddenInput()}handleKeyboardButtonClick(){this.showQuickKeys=!0,this.updateTerminalTransform(),this.directKeyboardManager.focusHiddenInput(),this.requestUpdate()}handleTerminalFitToggle(){this.terminalFitHorizontally=!this.terminalFitHorizontally;let e=this.querySelector("vibe-terminal");e?.handleFitToggle&&e.handleFitToggle()}handleMaxWidthToggle(){this.showWidthSelector=!this.showWidthSelector}handleWidthSelect(e){this.terminalMaxCols=e,this.preferencesManager.setMaxCols(e),this.showWidthSelector=!1,this.terminalLifecycleManager.setTerminalMaxCols(e);let i=this.querySelector("vibe-terminal");i?(i.maxCols=e,i.setUserOverrideWidth(!0),i.requestUpdate()):Ge.warn("Terminal component not found when setting width")}getCurrentWidthLabel(){let e=this.querySelector("vibe-terminal"),i=this.session?.id?.startsWith("fwd_");if(this.terminalMaxCols===0&&e?.initialCols>0&&!e.userOverrideWidth&&i)return`\u2264${e.initialCols}`;if(this.terminalMaxCols===0)return"\u221E";let s=mi.find(o=>o.value===this.terminalMaxCols);return s?s.label:this.terminalMaxCols.toString()}getWidthTooltip(){let e=this.querySelector("vibe-terminal"),i=this.session?.id?.startsWith("fwd_");return this.terminalMaxCols===0&&e?.initialCols>0&&!e.userOverrideWidth&&i?`Terminal width: Limited to native terminal width (${e.initialCols} columns)`:`Terminal width: ${this.terminalMaxCols===0?"Unlimited":`${this.terminalMaxCols} columns`}`}handleFontSizeChange(e){let i=Math.max(8,Math.min(32,e));this.terminalFontSize=i,this.preferencesManager.setFontSize(i),this.terminalLifecycleManager.setTerminalFontSize(i);let s=this.querySelector("vibe-terminal");s&&(s.fontSize=i,s.requestUpdate())}handleOpenFileBrowser(){this.showFileBrowser=!0}handleCloseFileBrowser(){this.showFileBrowser=!1}async handleInsertPath(e){let{path:i,type:s}=e.detail;if(!i||!this.session)return;let o=i.includes(" ")?`"${i}"`:i;this.inputManager&&await this.inputManager.sendInputText(o),Ge.log(`inserted ${s} path into terminal: ${o}`)}focusHiddenInput(){this.directKeyboardManager.focusHiddenInput()}handleTerminalClick(e){if(this.isMobile&&this.useDirectKeyboard){e.stopPropagation(),e.preventDefault();return}}async handleTerminalInput(e){let{text:i}=e.detail;this.inputManager&&i&&await this.inputManager.sendInputText(i)}updateTerminalTransform(){let e=0;this.showQuickKeys&&this.isMobile&&(e+=150),this.keyboardHeight>0&&(e+=this.keyboardHeight+10),e>0?this.terminalContainerHeight=`calc(100% - ${e}px)`:this.terminalContainerHeight="100%",Ge.log(`Terminal height updated: quickKeys=${this.showQuickKeys}, keyboardHeight=${this.keyboardHeight}, reduction=${e}px`),this.requestUpdate(),requestAnimationFrame(()=>{let i=this.querySelector("vibe-terminal");if(i){let s=i;typeof s.fitTerminal=="function"&&s.fitTerminal(),e>0&&setTimeout(()=>{i.scrollToBottom()},50)}})}refreshTerminalAfterMobileInput(){this.terminalLifecycleManager.getTerminal()&&setTimeout(()=>{let i=this.terminalLifecycleManager.getTerminal();if(i){let s=i;typeof s.fitTerminal=="function"&&s.fitTerminal(),i.scrollToBottom()}},300)}render(){return this.session?S`
      <style>
        session-view *,
        session-view *:focus,
        session-view *:focus-visible {
          outline: none !important;
          box-shadow: none !important;
        }
        session-view:focus {
          outline: 2px solid #00ff88 !important;
          outline-offset: -2px;
        }
      </style>
      <div
        class="flex flex-col bg-black font-mono relative"
        style="height: 100vh; height: 100dvh; outline: none !important; box-shadow: none !important;"
      >
        <!-- Session Header -->
        <session-header
          .session=${this.session}
          .showBackButton=${this.showBackButton}
          .showSidebarToggle=${this.showSidebarToggle}
          .sidebarCollapsed=${this.sidebarCollapsed}
          .terminalCols=${this.terminalCols}
          .terminalRows=${this.terminalRows}
          .terminalMaxCols=${this.terminalMaxCols}
          .terminalFontSize=${this.terminalFontSize}
          .customWidth=${this.customWidth}
          .showWidthSelector=${this.showWidthSelector}
          .widthLabel=${this.getCurrentWidthLabel()}
          .widthTooltip=${this.getWidthTooltip()}
          .onBack=${()=>this.handleBack()}
          .onSidebarToggle=${()=>this.handleSidebarToggle()}
          .onOpenFileBrowser=${()=>this.handleOpenFileBrowser()}
          .onMaxWidthToggle=${()=>this.handleMaxWidthToggle()}
          .onWidthSelect=${e=>this.handleWidthSelect(e)}
          .onFontSizeChange=${e=>this.handleFontSizeChange(e)}
          @close-width-selector=${()=>{this.showWidthSelector=!1,this.customWidth=""}}
        ></session-header>

        <!-- Terminal Container -->
        <div
          class="${this.terminalContainerHeight==="100%"?"flex-1":""} bg-black overflow-hidden min-h-0 relative ${this.session?.status==="exited"?"session-exited":""}"
          id="terminal-container"
          style="${this.terminalContainerHeight!=="100%"?`height: ${this.terminalContainerHeight}; flex: none; max-height: ${this.terminalContainerHeight};`:""} transition: height 0.3s ease-out;"
        >
          ${this.loadingAnimationManager.isLoading()?S`
                <!-- Loading overlay -->
                <div
                  class="absolute inset-0 bg-dark-bg bg-opacity-80 flex items-center justify-center z-10"
                >
                  <div class="text-dark-text font-mono text-center">
                    <div class="text-2xl mb-2">${this.loadingAnimationManager.getLoadingText()}</div>
                    <div class="text-sm text-dark-text-muted">Connecting to session...</div>
                  </div>
                </div>
              `:""}
          <!-- Terminal Component -->
          <vibe-terminal
            .sessionId=${this.session?.id||""}
            .sessionStatus=${this.session?.status||"running"}
            .cols=${80}
            .rows=${24}
            .fontSize=${this.terminalFontSize}
            .fitHorizontally=${!1}
            .maxCols=${this.terminalMaxCols}
            .initialCols=${this.session?.initialCols||0}
            .initialRows=${this.session?.initialRows||0}
            .disableClick=${this.isMobile&&this.useDirectKeyboard}
            .hideScrollButton=${this.showQuickKeys}
            class="w-full h-full p-0 m-0"
            @click=${this.handleTerminalClick}
            @terminal-input=${this.handleTerminalInput}
          ></vibe-terminal>
        </div>

        <!-- Floating Session Exited Banner (outside terminal container to avoid filter effects) -->
        ${this.session?.status==="exited"?S`
              <div
                class="fixed inset-0 flex items-center justify-center pointer-events-none z-[25]"
              >
                <div
                  class="bg-dark-bg-secondary border border-dark-border text-status-warning font-medium text-sm tracking-wide px-4 py-2 rounded-lg shadow-lg"
                >
                  SESSION EXITED
                </div>
              </div>
            `:""}

        <!-- Mobile Input Controls (only show when direct keyboard is disabled) -->
        ${this.isMobile&&!this.showMobileInput&&!this.useDirectKeyboard?S`
              <div class="flex-shrink-0 p-4" style="background: black;">
                <!-- First row: Arrow keys -->
                <div class="flex gap-2 mb-2">
                  <button
                    class="flex-1 font-mono px-3 py-2 text-sm transition-all cursor-pointer quick-start-btn"
                    @click=${()=>this.handleSpecialKey("arrow_up")}
                  >
                    <span class="text-xl">↑</span>
                  </button>
                  <button
                    class="flex-1 font-mono px-3 py-2 text-sm transition-all cursor-pointer quick-start-btn"
                    @click=${()=>this.handleSpecialKey("arrow_down")}
                  >
                    <span class="text-xl">↓</span>
                  </button>
                  <button
                    class="flex-1 font-mono px-3 py-2 text-sm transition-all cursor-pointer quick-start-btn"
                    @click=${()=>this.handleSpecialKey("arrow_left")}
                  >
                    <span class="text-xl">←</span>
                  </button>
                  <button
                    class="flex-1 font-mono px-3 py-2 text-sm transition-all cursor-pointer quick-start-btn"
                    @click=${()=>this.handleSpecialKey("arrow_right")}
                  >
                    <span class="text-xl">→</span>
                  </button>
                </div>

                <!-- Second row: Special keys -->
                <div class="flex gap-2">
                  <button
                    class="font-mono text-sm transition-all cursor-pointer w-16 quick-start-btn"
                    @click=${()=>this.handleSpecialKey("escape")}
                  >
                    ESC
                  </button>
                  <button
                    class="font-mono text-sm transition-all cursor-pointer w-16 quick-start-btn"
                    @click=${()=>this.handleSpecialKey("	")}
                  >
                    <span class="text-xl">⇥</span>
                  </button>
                  <button
                    class="flex-1 font-mono px-3 py-2 text-sm transition-all cursor-pointer quick-start-btn"
                    @click=${this.handleMobileInputToggle}
                  >
                    ABC123
                  </button>
                  <button
                    class="font-mono text-sm transition-all cursor-pointer w-16 quick-start-btn"
                    @click=${this.handleCtrlAlphaToggle}
                  >
                    CTRL
                  </button>
                  <button
                    class="font-mono text-sm transition-all cursor-pointer w-16 quick-start-btn"
                    @click=${()=>this.handleSpecialKey("enter")}
                  >
                    <span class="text-xl">⏎</span>
                  </button>
                </div>
              </div>
            `:""}

        <!-- Mobile Input Overlay -->
        <mobile-input-overlay
          .visible=${this.isMobile&&this.showMobileInput}
          .mobileInputText=${this.mobileInputText}
          .keyboardHeight=${this.keyboardHeight}
          .touchStartX=${this.touchStartX}
          .touchStartY=${this.touchStartY}
          .onSend=${e=>this.handleMobileInputSendOnly(e)}
          .onSendWithEnter=${e=>this.handleMobileInputSend(e)}
          .onCancel=${()=>this.handleMobileInputCancel()}
          .onTextChange=${e=>{this.mobileInputText=e}}
          .handleBack=${this.handleBack.bind(this)}
        ></mobile-input-overlay>

        <!-- Ctrl+Alpha Overlay -->
        <ctrl-alpha-overlay
          .visible=${this.isMobile&&this.showCtrlAlpha}
          .ctrlSequence=${this.ctrlSequence}
          .keyboardHeight=${this.keyboardHeight}
          .onCtrlKey=${e=>this.handleCtrlKey(e)}
          .onSendSequence=${()=>this.handleSendCtrlSequence()}
          .onClearSequence=${()=>this.handleClearCtrlSequence()}
          .onCancel=${()=>this.handleCtrlAlphaCancel()}
        ></ctrl-alpha-overlay>

        <!-- Floating Keyboard Button (for direct keyboard mode on mobile) -->
        ${this.isMobile&&this.useDirectKeyboard&&!this.showQuickKeys?S`
              <div
                class="keyboard-button"
                @pointerdown=${e=>{e.preventDefault(),e.stopPropagation()}}
                @click=${e=>{e.preventDefault(),e.stopPropagation(),this.handleKeyboardButtonClick()}}
                title="Show keyboard"
              >
                ⌨
              </div>
            `:""}

        <!-- Terminal Quick Keys (for direct keyboard mode) -->
        <terminal-quick-keys
          .visible=${this.isMobile&&this.useDirectKeyboard&&this.showQuickKeys}
          .onKeyPress=${this.directKeyboardManager.handleQuickKeyPress}
        ></terminal-quick-keys>

        <!-- File Browser Modal -->
        <file-browser
          .visible=${this.showFileBrowser}
          .mode=${"browse"}
          .session=${this.session}
          @browser-cancel=${this.handleCloseFileBrowser}
          @insert-path=${this.handleInsertPath}
        ></file-browser>
      </div>
    `:S`
        <div class="fixed inset-0 bg-dark-bg flex items-center justify-center">
          <div class="text-dark-text font-mono text-center">
            <div class="text-2xl mb-2">${this.loadingAnimationManager.getLoadingText()}</div>
            <div class="text-sm text-dark-text-muted">Waiting for session...</div>
          </div>
        </div>
      `}};_([$({type:Object})],Q.prototype,"session",2),_([$({type:Boolean})],Q.prototype,"showBackButton",2),_([$({type:Boolean})],Q.prototype,"showSidebarToggle",2),_([$({type:Boolean})],Q.prototype,"sidebarCollapsed",2),_([$({type:Boolean})],Q.prototype,"disableFocusManagement",2),_([A()],Q.prototype,"connected",2),_([A()],Q.prototype,"showMobileInput",2),_([A()],Q.prototype,"mobileInputText",2),_([A()],Q.prototype,"isMobile",2),_([A()],Q.prototype,"touchStartX",2),_([A()],Q.prototype,"touchStartY",2),_([A()],Q.prototype,"terminalCols",2),_([A()],Q.prototype,"terminalRows",2),_([A()],Q.prototype,"showCtrlAlpha",2),_([A()],Q.prototype,"terminalFitHorizontally",2),_([A()],Q.prototype,"terminalMaxCols",2),_([A()],Q.prototype,"showWidthSelector",2),_([A()],Q.prototype,"customWidth",2),_([A()],Q.prototype,"showFileBrowser",2),_([A()],Q.prototype,"terminalFontSize",2),_([A()],Q.prototype,"terminalContainerHeight",2),_([A()],Q.prototype,"ctrlSequence",2),_([A()],Q.prototype,"useDirectKeyboard",2),_([A()],Q.prototype,"showQuickKeys",2),_([A()],Q.prototype,"keyboardHeight",2),Q=_([z("session-view")],Q);Pe();var we=class extends F{constructor(){super(...arguments);this.logs=[];this.loading=!0;this.error="";this.filter="";this.levelFilter=new Set(["error","warn","log","debug"]);this.autoScroll=!0;this.logSize="";this.showClient=!0;this.showServer=!0;this.isFirstLoad=!0}createRenderRoot(){return this}connectedCallback(){super.connectedCallback(),this.loadLogs(),this.refreshInterval=window.setInterval(()=>this.loadLogs(),2e3)}disconnectedCallback(){super.disconnectedCallback(),this.refreshInterval&&clearInterval(this.refreshInterval)}async loadLogs(){try{let e=await fetch("/api/logs/info",{headers:{...j.getAuthHeader()}});if(e.ok){let o=await e.json();this.logSize=o.sizeHuman||""}let i=await fetch("/api/logs/raw",{headers:{...j.getAuthHeader()}});if(!i.ok)throw new Error("Failed to load logs");let s=await i.text();this.parseLogs(s),this.loading=!1,this.autoScroll&&requestAnimationFrame(()=>{let o=this.querySelector(".log-container");o&&(this.isFirstLoad?(o.scrollTop=o.scrollHeight,this.isFirstLoad=!1):o.scrollHeight-o.scrollTop-o.clientHeight<100&&(o.scrollTop=o.scrollHeight))})}catch(e){this.error=e instanceof Error?e.message:"Failed to load logs",this.loading=!1}}formatRelativeTime(e){let i=new Date(e),o=new Date().getTime()-i.getTime(),c=Math.floor(o/1e3),r=Math.floor(c/60),a=Math.floor(r/60);return c<60?`${c}s ago`:r<60?`${r}m ago`:a<24?`${a}h ago`:i.toLocaleTimeString("en-US",{hour12:!1})}parseLogs(e){let i=e.split(`
`),s=[],o=null;for(let c of i){if(!c.trim())continue;let r=c.match(/^(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+(.*)$/);if(r){o&&s.push(o);let[,a,g,m,l]=r,v=m.startsWith("CLIENT:");o={timestamp:a,level:g.trim().toLowerCase(),module:v?m.substring(7):m,message:l,isClient:v}}else o?o.message+=`
${c}`:s.push({timestamp:"",level:"log",module:"unknown",message:c,isClient:!1})}o&&s.push(o),this.logs=s}toggleLevel(e){this.levelFilter.has(e)?this.levelFilter.delete(e):this.levelFilter.add(e),this.levelFilter=new Set(this.levelFilter)}async clearLogs(){if(confirm("Are you sure you want to clear all logs?"))try{if(!(await fetch("/api/logs/clear",{method:"DELETE",headers:{...j.getAuthHeader()}})).ok)throw new Error("Failed to clear logs");this.logs=[],this.logSize="0 Bytes"}catch(e){this.error=e instanceof Error?e.message:"Failed to clear logs"}}async downloadLogs(){try{let e=await fetch("/api/logs/raw",{headers:{...j.getAuthHeader()}});if(!e.ok)throw new Error("Failed to download logs");let i=await e.blob(),s=URL.createObjectURL(i),o=document.createElement("a");o.href=s,o.download=`vibetunnel-logs-${new Date().toISOString().split("T")[0]}.txt`,o.click(),URL.revokeObjectURL(s)}catch(e){this.error=e instanceof Error?e.message:"Failed to download logs"}}get filteredLogs(){return this.logs.filter(e=>{if(!this.levelFilter.has(e.level)||!this.showClient&&e.isClient||!this.showServer&&!e.isClient)return!1;if(this.filter){let i=this.filter.toLowerCase();return e.module.toLowerCase().includes(i)||e.message.toLowerCase().includes(i)}return!0})}render(){let e=S`
      <style>
        .log-container {
          /* Hide scrollbar by default */
          scrollbar-width: none; /* Firefox */
        }

        .log-container::-webkit-scrollbar {
          width: 8px;
          background: transparent;
        }

        .log-container::-webkit-scrollbar-track {
          background: transparent;
        }

        .log-container::-webkit-scrollbar-thumb {
          background: transparent;
          border-radius: 4px;
        }

        /* Show scrollbar on hover */
        .log-container:hover::-webkit-scrollbar-thumb {
          background: rgba(255, 255, 255, 0.2);
        }

        .log-container::-webkit-scrollbar-thumb:hover {
          background: rgba(255, 255, 255, 0.3);
        }

        /* Firefox */
        .log-container:hover {
          scrollbar-width: thin;
          scrollbar-color: rgba(255, 255, 255, 0.2) transparent;
        }
      </style>
    `;if(this.loading)return S`
        <div class="flex items-center justify-center h-screen bg-dark-bg text-dark-text">
          <div class="text-center">
            <div
              class="animate-spin rounded-full h-12 w-12 border-4 border-accent-green border-t-transparent mb-4"
            ></div>
            <div>Loading logs...</div>
          </div>
        </div>
      `;let i=["error","warn","log","debug"];return S`
      ${e}
      <div class="flex flex-col h-full bg-dark-bg text-dark-text font-mono">
        <!-- Header - single row on desktop, two rows on mobile -->
        <div class="bg-dark-bg-secondary border-b border-dark-border p-3 sm:p-4">
          <!-- Mobile layout (two rows) -->
          <div class="sm:hidden">
            <!-- Top row with back button and title -->
            <div class="flex items-center gap-2 mb-3">
              <!-- Back button -->
              <button
                class="p-2 bg-dark-bg border border-dark-border rounded text-sm text-dark-text hover:border-accent-green hover:text-accent-green transition-colors flex items-center gap-1 flex-shrink-0"
                @click=${()=>{window.location.href="/"}}
              >
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                >
                  <path d="M15 18l-6-6 6-6" />
                </svg>
              </button>

              <h1
                class="text-base font-bold text-accent-green flex items-center gap-2 flex-shrink-0"
              >
                <terminal-icon size="20"></terminal-icon>
                <span>System Logs</span>
              </h1>

              <!-- Auto-scroll toggle (mobile position) -->
              <div class="ml-auto">
                <button
                  class="p-2 text-xs uppercase font-bold rounded transition-colors ${this.autoScroll?"bg-accent-green text-dark-bg":"bg-dark-bg-tertiary text-dark-text-muted border border-dark-border"}"
                  @click=${()=>{this.autoScroll=!this.autoScroll}}
                  title="Auto Scroll"
                >
                  <svg
                    width="16"
                    height="16"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                  >
                    <path d="M12 5v14M19 12l-7 7-7-7" />
                  </svg>
                </button>
              </div>
            </div>

            <!-- Filters row -->
            <div class="flex flex-wrap gap-2">
              <!-- Search input -->
              <input
                type="text"
                class="px-3 py-1.5 bg-dark-bg border border-dark-border rounded text-sm text-dark-text placeholder-dark-text-muted focus:outline-none focus:border-accent-green transition-colors w-full"
                placeholder="Filter logs..."
                .value=${this.filter}
                @input=${s=>{this.filter=s.target.value}}
              />

              <!-- Filters container -->
              <div class="flex gap-2 items-center">
                <!-- Level filters -->
                <div class="flex gap-1">
                  ${i.map(s=>S`
                      <button
                        class="px-1.5 py-1 text-xs uppercase font-bold rounded transition-colors ${this.levelFilter.has(s)?s==="error"?"bg-status-error text-dark-bg":s==="warn"?"bg-status-warning text-dark-bg":s==="debug"?"bg-dark-text-muted text-dark-bg":"bg-dark-text text-dark-bg":"bg-dark-bg-tertiary text-dark-text-muted border border-dark-border"}"
                        @click=${()=>this.toggleLevel(s)}
                        title="${s} logs"
                      >
                        ${s==="error"?"ERR":s==="warn"?"WRN":s==="debug"?"DBG":"LOG"}
                      </button>
                    `)}
                </div>

                <!-- Client/Server toggles -->
                <div class="flex gap-1">
                  <button
                    class="px-1.5 py-1 text-xs uppercase font-bold rounded transition-colors ${this.showClient?"bg-orange-500 text-dark-bg":"bg-dark-bg-tertiary text-dark-text-muted border border-dark-border"}"
                    @click=${()=>{this.showClient=!this.showClient}}
                    title="Client logs"
                  >
                    C
                  </button>
                  <button
                    class="px-1.5 py-1 text-xs uppercase font-bold rounded transition-colors ${this.showServer?"bg-accent-green text-dark-bg":"bg-dark-bg-tertiary text-dark-text-muted border border-dark-border"}"
                    @click=${()=>{this.showServer=!this.showServer}}
                    title="Server logs"
                  >
                    S
                  </button>
                </div>
              </div>
            </div>
          </div>

          <!-- Desktop layout (single row) -->
          <div class="hidden sm:flex items-center gap-3">
            <!-- Back button -->
            <button
              class="px-3 py-1.5 bg-dark-bg border border-dark-border rounded text-sm text-dark-text hover:border-accent-green hover:text-accent-green transition-colors flex items-center gap-2 flex-shrink-0"
              @click=${()=>{window.location.href="/"}}
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
              >
                <path d="M15 18l-6-6 6-6" />
              </svg>
              Back
            </button>

            <h1 class="text-lg font-bold text-accent-green flex items-center gap-2 flex-shrink-0">
              <terminal-icon size="24"></terminal-icon>
              <span>System Logs</span>
            </h1>

            <div class="flex-1 flex flex-wrap gap-2 items-center justify-end">
              <!-- Search input -->
              <input
                type="text"
                class="px-3 py-1.5 bg-dark-bg border border-dark-border rounded text-sm text-dark-text placeholder-dark-text-muted focus:outline-none focus:border-accent-green transition-colors flex-1 sm:flex-initial sm:w-64 md:w-80"
                placeholder="Filter logs..."
                .value=${this.filter}
                @input=${s=>{this.filter=s.target.value}}
              />

              <!-- Level filters -->
              <div class="flex gap-1">
                ${i.map(s=>S`
                    <button
                      class="px-2 py-1 text-xs uppercase font-bold rounded transition-colors ${this.levelFilter.has(s)?s==="error"?"bg-status-error text-dark-bg":s==="warn"?"bg-status-warning text-dark-bg":s==="debug"?"bg-dark-text-muted text-dark-bg":"bg-dark-text text-dark-bg":"bg-dark-bg-tertiary text-dark-text-muted border border-dark-border"}"
                      @click=${()=>this.toggleLevel(s)}
                    >
                      ${s}
                    </button>
                  `)}
              </div>

              <!-- Client/Server toggles -->
              <div class="flex gap-1">
                <button
                  class="px-2 py-1 text-xs uppercase font-bold rounded transition-colors ${this.showClient?"bg-orange-500 text-dark-bg":"bg-dark-bg-tertiary text-dark-text-muted border border-dark-border"}"
                  @click=${()=>{this.showClient=!this.showClient}}
                >
                  CLIENT
                </button>
                <button
                  class="px-2 py-1 text-xs uppercase font-bold rounded transition-colors ${this.showServer?"bg-accent-green text-dark-bg":"bg-dark-bg-tertiary text-dark-text-muted border border-dark-border"}"
                  @click=${()=>{this.showServer=!this.showServer}}
                >
                  SERVER
                </button>
              </div>

              <!-- Auto-scroll toggle -->
              <button
                class="px-3 py-1 text-xs uppercase font-bold rounded transition-colors ${this.autoScroll?"bg-accent-green text-dark-bg":"bg-dark-bg-tertiary text-dark-text-muted border border-dark-border"}"
                @click=${()=>{this.autoScroll=!this.autoScroll}}
              >
                AUTO SCROLL
              </button>
            </div>
          </div>
        </div>

        <!-- Log container -->
        <div
          class="log-container flex-1 overflow-y-auto p-4 bg-dark-bg font-mono text-xs leading-relaxed"
        >
          ${this.filteredLogs.length===0?S`
                <div class="flex items-center justify-center h-full text-dark-text-muted">
                  <div class="text-center">
                    <div>No logs to display</div>
                  </div>
                </div>
              `:this.filteredLogs.map(s=>{let o=s.message.includes(`
`),c=s.message.split(`
`);return S`
                  <div
                    class="group hover:bg-dark-bg-secondary/50 transition-colors rounded ${s.isClient?"bg-orange-500/5 pl-2":"pl-2"}"
                  >
                    <!-- Desktop layout (hidden on mobile) -->
                    <div class="hidden sm:flex items-start gap-2 py-0.5">
                      <!-- Timestamp -->
                      <span class="text-dark-text-muted w-16 flex-shrink-0 opacity-50"
                        >${this.formatRelativeTime(s.timestamp)}</span
                      >

                      <!-- Level -->
                      <span
                        class="w-10 text-center font-mono uppercase tracking-wider flex-shrink-0 ${s.level==="error"?"text-red-500 bg-red-500/20 px-1 rounded font-bold":s.level==="warn"?"text-yellow-500 bg-yellow-500/20 px-1 rounded font-bold":s.level==="debug"?"text-gray-600":"text-gray-500"}"
                        >${s.level==="error"?"ERR":s.level==="warn"?"WRN":s.level==="debug"?"DBG":"LOG"}</span
                      >

                      <!-- Source indicator -->
                      <span
                        class="flex-shrink-0 ${s.isClient?"text-orange-400 font-bold":"text-green-600"}"
                        >${s.isClient?"\u25C6 C":"\u25B8 S"}</span
                      >

                      <!-- Module -->
                      <span class="text-gray-600 flex-shrink-0 font-mono">${s.module}</span>

                      <!-- Separator -->
                      <span class="text-gray-700 flex-shrink-0">│</span>

                      <!-- Message -->
                      <span
                        class="flex-1 ${s.level==="error"?"text-red-400":s.level==="warn"?"text-yellow-400":s.level==="debug"?"text-gray-600":s.isClient?"text-orange-200":"text-gray-300"}"
                        >${c[0]}</span
                      >
                    </div>

                    <!-- Mobile layout (visible only on mobile) -->
                    <div class="sm:hidden py-1">
                      <div class="flex items-center gap-2 text-xs">
                        <span class="text-dark-text-muted opacity-50"
                          >${this.formatRelativeTime(s.timestamp)}</span
                        >
                        <span
                          class="${s.level==="error"?"text-red-500 font-bold":s.level==="warn"?"text-yellow-500 font-bold":s.level==="debug"?"text-gray-600":"text-gray-500"} uppercase"
                          >${s.level}</span
                        >
                        <span class="${s.isClient?"text-orange-400":"text-green-600"}"
                          >${s.isClient?"[C]":"[S]"}</span
                        >
                        <span class="text-gray-600">${s.module}</span>
                      </div>
                      <div
                        class="mt-1 ${s.level==="error"?"text-red-400":s.level==="warn"?"text-yellow-400":s.level==="debug"?"text-gray-600":s.isClient?"text-orange-200":"text-gray-300"}"
                      >
                        ${c[0]}
                      </div>
                    </div>
                    ${o?S`
                          <div
                            class="hidden sm:block ml-36 ${s.level==="error"?"text-red-400":s.level==="warn"?"text-yellow-400":"text-gray-500"}"
                          >
                            ${c.slice(1).map(r=>S`<div class="py-0.5">${r}</div>`)}
                          </div>
                          <div
                            class="sm:hidden mt-1 ${s.level==="error"?"text-red-400":s.level==="warn"?"text-yellow-400":"text-gray-500"}"
                          >
                            ${c.slice(1).map(r=>S`<div class="py-0.5">${r}</div>`)}
                          </div>
                        `:""}
                  </div>
                `})}
        </div>

        <!-- Footer -->
        <div
          class="flex items-center justify-between p-3 bg-dark-bg-secondary border-t border-dark-border text-xs"
        >
          <div class="text-dark-text-muted">
            ${this.filteredLogs.length} / ${this.logs.length} logs
            ${this.logSize?S` <span class="text-dark-text-muted">• ${this.logSize}</span>`:""}
          </div>
          <div class="flex gap-2">
            <button
              class="px-3 py-1 bg-dark-bg border border-dark-border rounded hover:border-accent-green hover:text-accent-green transition-colors"
              @click=${this.downloadLogs}
            >
              Download
            </button>
            <button
              class="px-3 py-1 bg-dark-bg border border-status-error text-status-error rounded hover:bg-status-error hover:text-dark-bg transition-colors"
              @click=${this.clearLogs}
            >
              Clear
            </button>
          </div>
        </div>
      </div>
    `}};_([A()],we.prototype,"logs",2),_([A()],we.prototype,"loading",2),_([A()],we.prototype,"error",2),_([A()],we.prototype,"filter",2),_([A()],we.prototype,"levelFilter",2),_([A()],we.prototype,"autoScroll",2),_([A()],we.prototype,"logSize",2),_([A()],we.prototype,"showClient",2),_([A()],we.prototype,"showServer",2),we=_([z("log-viewer")],we);Z();var tr=N("unified-settings"),ir={useDirectKeyboard:!0,showLogLink:!1},sr="vibetunnel_app_preferences",_e=class extends F{constructor(){super(...arguments);this.visible=!1;this.notificationPreferences={enabled:!1,sessionExit:!0,sessionStart:!1,sessionError:!0,systemAlerts:!0,soundEnabled:!0,vibrationEnabled:!0};this.permission="default";this.subscription=null;this.isLoading=!1;this.testingNotification=!1;this.hasNotificationChanges=!1;this.appPreferences=ir;this.mediaState=Ye.getCurrentState();this.handleKeyDown=e=>{e.key==="Escape"&&this.visible&&this.handleClose()}}createRenderRoot(){return this}connectedCallback(){super.connectedCallback(),this.initializeNotifications(),this.loadAppPreferences(),this.unsubscribeResponsive=Ye.subscribe(e=>{this.mediaState=e})}disconnectedCallback(){super.disconnectedCallback(),this.permissionChangeUnsubscribe&&this.permissionChangeUnsubscribe(),this.subscriptionChangeUnsubscribe&&this.subscriptionChangeUnsubscribe(),this.unsubscribeResponsive&&this.unsubscribeResponsive()}willUpdate(e){e.has("visible")&&(this.visible?(document.addEventListener("keydown",this.handleKeyDown),document.startViewTransition?.(()=>{this.requestUpdate()})):document.removeEventListener("keydown",this.handleKeyDown))}async initializeNotifications(){await ee.waitForInitialization(),this.permission=ee.getPermission(),this.subscription=ee.getSubscription(),this.notificationPreferences=ee.loadPreferences(),this.permissionChangeUnsubscribe=ee.onPermissionChange(e=>{this.permission=e}),this.subscriptionChangeUnsubscribe=ee.onSubscriptionChange(e=>{this.subscription=e})}loadAppPreferences(){try{let e=localStorage.getItem(sr);e&&(this.appPreferences={...ir,...JSON.parse(e)})}catch(e){tr.error("Failed to load app preferences",e)}}saveAppPreferences(){try{localStorage.setItem(sr,JSON.stringify(this.appPreferences)),window.dispatchEvent(new CustomEvent("app-preferences-changed",{detail:this.appPreferences}))}catch(e){tr.error("Failed to save app preferences",e)}}handleClose(){this.dispatchEvent(new CustomEvent("close"))}handleBackdropClick(e){e.target===e.currentTarget&&this.handleClose()}async handleToggleNotifications(){if(!this.isLoading){this.isLoading=!0;try{if(this.notificationPreferences.enabled)await ee.unsubscribe(),this.notificationPreferences={...this.notificationPreferences,enabled:!1},ee.savePreferences(this.notificationPreferences),this.dispatchEvent(new CustomEvent("notifications-disabled"));else{let e=await ee.requestPermission();e==="granted"?await ee.subscribe()?(this.notificationPreferences={...this.notificationPreferences,enabled:!0},ee.savePreferences(this.notificationPreferences),this.dispatchEvent(new CustomEvent("notifications-enabled"))):this.dispatchEvent(new CustomEvent("error",{detail:"Failed to subscribe to notifications"})):this.dispatchEvent(new CustomEvent("error",{detail:e==="denied"?"Notifications permission denied":"Notifications permission not granted"}))}}finally{this.isLoading=!1}}}async handleTestNotification(){if(!this.testingNotification){this.testingNotification=!0;try{await ee.testNotification(),this.dispatchEvent(new CustomEvent("success",{detail:"Test notification sent"}))}finally{this.testingNotification=!1}}}async handleNotificationPreferenceChange(e,i){this.notificationPreferences={...this.notificationPreferences,[e]:i},this.hasNotificationChanges=!0,ee.savePreferences(this.notificationPreferences)}handleAppPreferenceChange(e,i){this.appPreferences={...this.appPreferences,[e]:i},this.saveAppPreferences()}get isNotificationsSupported(){return ee.isSupported()}get isNotificationsEnabled(){return this.notificationPreferences.enabled&&this.permission==="granted"&&!!this.subscription}renderSubscriptionStatus(){return this.subscription||ee.isSubscribed()?S`
        <div class="flex items-center space-x-2">
          <span class="text-status-success font-mono">✓</span>
          <span class="text-sm text-dark-text">Active</span>
        </div>
      `:this.permission==="granted"?S`
        <div class="flex items-center space-x-2">
          <span class="text-status-warning font-mono">!</span>
          <span class="text-sm text-dark-text">Not subscribed</span>
        </div>
      `:S`
        <div class="flex items-center space-x-2">
          <span class="text-status-error font-mono">✗</span>
          <span class="text-sm text-dark-text">Disabled</span>
        </div>
      `}isIOSSafari(){let e=navigator.userAgent.toLowerCase();return/iphone|ipad|ipod/.test(e)}isStandalone(){return window.matchMedia("(display-mode: standalone)").matches||"standalone"in window.navigator&&window.navigator.standalone===!0}render(){return this.visible?S`
      <div class="modal-backdrop flex items-center justify-center" @click=${this.handleBackdropClick}>
        <div
          class="modal-content font-mono text-sm w-full max-w-[calc(100vw-1rem)] sm:max-w-md lg:max-w-2xl mx-2 sm:mx-4 max-h-[calc(100vh-2rem)] overflow-hidden flex flex-col"
          style="view-transition-name: settings-modal"
        >
          <!-- Header -->
          <div class="p-4 pb-4 border-b border-dark-border relative flex-shrink-0">
            <h2 class="text-accent-green text-lg font-bold">Settings</h2>
            <button
              class="absolute top-4 right-4 text-dark-text-muted hover:text-dark-text transition-colors p-1"
              @click=${this.handleClose}
              title="Close"
              aria-label="Close settings"
            >
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <!-- Content -->
          <div class="flex-1 overflow-y-auto p-4 space-y-6">
            ${this.renderNotificationSettings()}
            ${this.renderAppSettings()}
          </div>
        </div>
      </div>
    `:S``}renderNotificationSettings(){let e=this.isIOSSafari(),i=this.isStandalone(),s=this.permission==="granted"&&this.subscription;return S`
      <div class="space-y-4">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-md font-bold text-dark-text">Notifications</h3>
          ${this.renderSubscriptionStatus()}
        </div>
        
        ${this.isNotificationsSupported?S`
              <!-- Main toggle -->
              <div class="flex items-center justify-between p-4 bg-dark-bg-tertiary rounded-lg border border-dark-border">
                <div class="flex-1">
                  <label class="text-dark-text font-medium">Enable Notifications</label>
                  <p class="text-dark-text-muted text-xs mt-1">
                    Receive alerts for session events
                  </p>
                </div>
                <button
                  role="switch"
                  aria-checked="${this.isNotificationsEnabled}"
                  @click=${this.handleToggleNotifications}
                  ?disabled=${this.isLoading}
                  class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-dark-bg ${this.isNotificationsEnabled?"bg-accent-green":"bg-dark-border"}"
                >
                  <span
                    class="inline-block h-5 w-5 transform rounded-full bg-white transition-transform ${this.isNotificationsEnabled?"translate-x-5":"translate-x-0.5"}"
                  ></span>
                </button>
              </div>

              ${this.isNotificationsEnabled?S`
                    <!-- Notification types -->
                    <div class="mt-4 space-y-4">
                      <div>
                        <h4 class="text-sm font-medium text-dark-text-muted mb-3">Notification Types</h4>
                        <div class="space-y-2 bg-dark-bg rounded-lg p-3">
                          ${this.renderNotificationToggle("sessionExit","Session Exit","When a session terminates")}
                          ${this.renderNotificationToggle("sessionStart","Session Start","When a new session starts")}
                          ${this.renderNotificationToggle("sessionError","Session Errors","When errors occur in sessions")}
                          ${this.renderNotificationToggle("systemAlerts","System Alerts","Important system notifications")}
                        </div>
                      </div>

                      <!-- Sound and vibration -->
                      <div>
                        <h4 class="text-sm font-medium text-dark-text-muted mb-3">Notification Behavior</h4>
                        <div class="space-y-2 bg-dark-bg rounded-lg p-3">
                          ${this.renderNotificationToggle("soundEnabled","Sound","Play sound with notifications")}
                          ${this.renderNotificationToggle("vibrationEnabled","Vibration","Vibrate device with notifications")}
                        </div>
                      </div>
                    </div>

                    <!-- Test button -->
                    <div class="flex items-center justify-between pt-3 mt-3 border-t border-dark-border">
                      <p class="text-xs text-dark-text-muted">Test your notification settings</p>
                      <button
                        class="btn-secondary text-xs px-3 py-1.5"
                        @click=${this.handleTestNotification}
                        ?disabled=${!s||this.testingNotification}
                        title=${s?"Send test notification":"Enable notifications first"}
                      >
                        ${this.testingNotification?"Sending...":"Test Notification"}
                      </button>
                    </div>
                  `:""}
            `:S`
              <div class="p-4 bg-status-warning bg-opacity-10 border border-status-warning rounded-lg">
                ${e&&!i?S`
                      <p class="text-sm text-status-warning mb-2">
                        Push notifications require installing this app to your home screen.
                      </p>
                      <p class="text-xs text-status-warning opacity-80">
                        Tap the share button in Safari and select "Add to Home Screen" to enable push notifications.
                      </p>
                    `:S`
                      <p class="text-sm text-status-warning">
                        Push notifications are not supported in this browser.
                      </p>
                    `}
              </div>
            `}
      </div>
    `}renderNotificationToggle(e,i,s){return S`
      <div class="flex items-center justify-between py-2">
        <div class="flex-1 pr-4">
          <label class="text-dark-text text-sm font-medium">${i}</label>
          <p class="text-dark-text-muted text-xs">${s}</p>
        </div>
        <button
          role="switch"
          aria-checked="${this.notificationPreferences[e]}"
          @click=${()=>this.handleNotificationPreferenceChange(e,!this.notificationPreferences[e])}
          class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-dark-bg ${this.notificationPreferences[e]?"bg-accent-green":"bg-dark-border"}"
        >
          <span
            class="inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${this.notificationPreferences[e]?"translate-x-4":"translate-x-0.5"}"
          ></span>
        </button>
      </div>
    `}renderAppSettings(){return S`
      <div class="space-y-4">
        <h3 class="text-md font-bold text-dark-text mb-3">Application</h3>
        
        <!-- Direct keyboard input (Mobile only) -->
        ${this.mediaState.isMobile?S`
              <div class="flex items-center justify-between p-4 bg-dark-bg-tertiary rounded-lg border border-dark-border">
                <div class="flex-1">
                  <label class="text-dark-text font-medium">
                    Use Direct Keyboard
                  </label>
                  <p class="text-dark-text-muted text-xs mt-1">
                    Capture keyboard input directly without showing a text field (desktop-like experience)
                  </p>
                </div>
                <button
                  role="switch"
                  aria-checked="${this.appPreferences.useDirectKeyboard}"
                  @click=${()=>this.handleAppPreferenceChange("useDirectKeyboard",!this.appPreferences.useDirectKeyboard)}
                  class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-dark-bg ${this.appPreferences.useDirectKeyboard?"bg-accent-green":"bg-dark-border"}"
                >
                  <span
                    class="inline-block h-5 w-5 transform rounded-full bg-white transition-transform ${this.appPreferences.useDirectKeyboard?"translate-x-5":"translate-x-0.5"}"
                  ></span>
                </button>
              </div>
            `:""}

        <!-- Show log link -->
        <div class="flex items-center justify-between p-4 bg-dark-bg-tertiary rounded-lg border border-dark-border">
          <div class="flex-1">
            <label class="text-dark-text font-medium">Show Log Link</label>
            <p class="text-dark-text-muted text-xs mt-1">
              Display log link for debugging
            </p>
          </div>
          <button
            role="switch"
            aria-checked="${this.appPreferences.showLogLink}"
            @click=${()=>this.handleAppPreferenceChange("showLogLink",!this.appPreferences.showLogLink)}
            class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-dark-bg ${this.appPreferences.showLogLink?"bg-accent-green":"bg-dark-border"}"
          >
            <span
              class="inline-block h-5 w-5 transform rounded-full bg-white transition-transform ${this.appPreferences.showLogLink?"translate-x-5":"translate-x-0.5"}"
            ></span>
          </button>
        </div>
      </div>
    `}};_([$({type:Boolean})],_e.prototype,"visible",2),_([A()],_e.prototype,"notificationPreferences",2),_([A()],_e.prototype,"permission",2),_([A()],_e.prototype,"subscription",2),_([A()],_e.prototype,"isLoading",2),_([A()],_e.prototype,"testingNotification",2),_([A()],_e.prototype,"hasNotificationChanges",2),_([A()],_e.prototype,"appPreferences",2),_([A()],_e.prototype,"mediaState",2),_e=_([z("unified-settings")],_e);var xe=class extends F{constructor(){super(...arguments);this.loading=!1;this.error="";this.success="";this.currentUserId="";this.loginPassword="";this.userAvatar="";this.authConfig={enableSSHKeys:!1,disallowUserPassword:!1,noAuth:!1};this.isMobile=!1;this.handleOpenSettings=()=>{console.log("\u{1F527} Auth-login: handleOpenSettings called"),this.dispatchEvent(new CustomEvent("open-settings",{bubbles:!0}))}}createRenderRoot(){return this}async connectedCallback(){super.connectedCallback(),console.log("\u{1F50C} Auth login component connected"),this.unsubscribeResponsive=Ye.subscribe(e=>{this.isMobile=e.isMobile}),await this.loadUserInfo()}disconnectedCallback(){super.disconnectedCallback(),this.unsubscribeResponsive&&this.unsubscribeResponsive()}async loadUserInfo(){try{try{let e=await fetch("/api/auth/config");e.ok?(this.authConfig=await e.json(),console.log("\u2699\uFE0F Auth config loaded:",this.authConfig)):console.warn("\u26A0\uFE0F Failed to load auth config, using defaults:",e.status)}catch(e){console.error("\u274C Error loading auth config:",e)}this.currentUserId=await this.authClient.getCurrentSystemUser(),console.log("\u{1F464} Current user:",this.currentUserId),this.authConfig.noAuth||(this.userAvatar=await this.authClient.getUserAvatar(this.currentUserId),console.log("\u{1F5BC}\uFE0F User avatar loaded")),this.authConfig.noAuth&&(console.log("\u{1F513} No auth required, auto-logging in"),this.dispatchEvent(new CustomEvent("auth-success",{detail:{success:!0,userId:this.currentUserId,authMethod:"no-auth"}})))}catch{this.error="Failed to load user information"}}async handlePasswordLogin(e){if(e.preventDefault(),!this.loading){console.log("\u{1F510} Attempting password authentication..."),this.loading=!0,this.error="";try{let i=await this.authClient.authenticateWithPassword(this.currentUserId,this.loginPassword);console.log("\u{1F3AB} Password auth result:",i),i.success?(this.loginPassword="",this.dispatchEvent(new CustomEvent("auth-success",{detail:i}))):this.error=i.error||"Password authentication failed"}catch{this.error="Password authentication failed"}finally{this.loading=!1}}}async handleSSHKeyAuth(){if(!this.loading){console.log("\u{1F510} Attempting SSH key authentication..."),this.loading=!0,this.error="";try{let e=await this.authClient.authenticate(this.currentUserId);console.log("\u{1F3AF} SSH auth result:",e),e.success?this.dispatchEvent(new CustomEvent("auth-success",{detail:e})):this.error=e.error||"SSH key authentication failed. Please try password login."}catch(e){console.error("SSH key authentication error:",e),this.error="SSH key authentication failed"}finally{this.loading=!1}}}handleShowSSHKeyManager(){this.dispatchEvent(new CustomEvent("show-ssh-key-manager"))}render(){return console.log("\u{1F50D} Rendering auth login","enableSSHKeys:",this.authConfig.enableSSHKeys,"noAuth:",this.authConfig.noAuth),S`
      <div class="auth-container">
        <!-- Settings button in top right corner -->
        <button
          class="absolute top-4 right-4 p-2 text-dark-text-muted hover:text-dark-text transition-colors"
          @click=${this.handleOpenSettings}
          title="Settings"
        >
          <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd"/>
          </svg>
        </button>
        
        <div class="w-full max-w-sm">
          <div class="auth-header">
            <div class="flex flex-col items-center gap-2 sm:gap-3 mb-4 sm:mb-8">
              <terminal-icon
                size="${this.isMobile?"48":"56"}"
                style="filter: drop-shadow(0 0 15px rgba(124, 230, 161, 0.4));"
              ></terminal-icon>
              <h2 class="auth-title text-2xl sm:text-3xl mt-1 sm:mt-2">VibeTunnel</h2>
              <p class="auth-subtitle text-xs sm:text-sm">Please authenticate to continue</p>
            </div>
          </div>

          ${this.error?S`
                <div
                  class="bg-status-error text-dark-bg px-3 py-1.5 rounded mb-3 font-mono text-xs sm:text-sm"
                  data-testid="error-message"
                >
                  ${this.error}
                  <button
                    @click=${()=>{this.error=""}}
                    class="ml-2 text-dark-bg hover:text-dark-text"
                    data-testid="error-close"
                  >
                    ✕
                  </button>
                </div>
              `:""}
          ${this.success?S`
                <div
                  class="bg-status-success text-dark-bg px-3 py-1.5 rounded mb-3 font-mono text-xs sm:text-sm"
                >
                  ${this.success}
                  <button
                    @click=${()=>{this.success=""}}
                    class="ml-2 text-dark-bg hover:text-dark-text"
                  >
                    ✕
                  </button>
                </div>
              `:""}

          <div class="auth-form">
            ${this.authConfig.disallowUserPassword?"":S`
                  <!-- Password Login Section (Primary) -->
                  <div class="p-5 sm:p-8">
                    <div class="flex flex-col items-center mb-4 sm:mb-6">
                      <div
                        class="w-24 h-24 sm:w-28 sm:h-28 rounded-full mb-3 sm:mb-4 overflow-hidden"
                        style="box-shadow: 0 0 25px rgba(124, 230, 161, 0.3);"
                      >
                        ${this.userAvatar?S`
                              <img
                                src="${this.userAvatar}"
                                alt="User Avatar"
                                class="w-full h-full object-cover"
                                width="80"
                                height="80"
                              />
                            `:S`
                              <div
                                class="w-full h-full bg-dark-bg-secondary flex items-center justify-center"
                              >
                                <svg
                                  class="w-12 h-12 sm:w-14 sm:h-14 text-dark-text-muted"
                                  fill="currentColor"
                                  viewBox="0 0 20 20"
                                >
                                  <path d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" />
                                </svg>
                              </div>
                            `}
                      </div>
                      <p class="text-dark-text text-base sm:text-lg font-medium">
                        Welcome back, ${this.currentUserId||"..."}
                      </p>
                    </div>
                    <form @submit=${this.handlePasswordLogin} class="space-y-3">
                      <div>
                        <input
                          type="password"
                          class="input-field"
                          data-testid="password-input"
                          placeholder="System Password"
                          .value=${this.loginPassword}
                          @input=${e=>{this.loginPassword=e.target.value}}
                          ?disabled=${this.loading}
                          required
                        />
                      </div>
                      <button
                        type="submit"
                        class="btn-primary w-full py-3 sm:py-4 mt-2"
                        data-testid="password-submit"
                        ?disabled=${this.loading||!this.loginPassword}
                      >
                        ${this.loading?"Authenticating...":"Login with Password"}
                      </button>
                    </form>
                  </div>
                `}
            ${this.authConfig.disallowUserPassword?S`
                  <!-- Avatar for SSH-only mode -->
                  <div class="ssh-key-item p-6 sm:p-8">
                    <div class="flex flex-col items-center mb-4 sm:mb-6">
                      <div
                        class="w-16 h-16 sm:w-20 sm:h-20 rounded-full mb-2 sm:mb-3 overflow-hidden border-2 border-dark-border"
                      >
                        ${this.userAvatar?S`
                              <img
                                src="${this.userAvatar}"
                                alt="User Avatar"
                                class="w-full h-full object-cover"
                                width="80"
                                height="80"
                              />
                            `:S`
                              <div
                                class="w-full h-full bg-dark-bg-secondary flex items-center justify-center"
                              >
                                <svg
                                  class="w-8 h-8 sm:w-10 sm:h-10 text-dark-text-muted"
                                  fill="currentColor"
                                  viewBox="0 0 20 20"
                                >
                                  <path d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" />
                                </svg>
                              </div>
                            `}
                      </div>
                      <p class="text-dark-text text-xs sm:text-sm">
                        ${this.currentUserId?`Welcome back, ${this.currentUserId}`:"Please authenticate to continue"}
                      </p>
                      <p class="text-dark-text-muted text-xs mt-1 sm:mt-2">
                        SSH key authentication required
                      </p>
                    </div>
                  </div>
                `:""}
            ${this.authConfig.enableSSHKeys===!0?S`
                  <!-- Divider (only show if password auth is also available) -->
                  ${this.authConfig.disallowUserPassword?"":S`
                        <div class="auth-divider py-2 sm:py-3">
                          <span>or</span>
                        </div>
                      `}

                  <!-- SSH Key Management Section -->
                  <div class="ssh-key-item p-6 sm:p-8">
                    <div class="flex items-center justify-between mb-3 sm:mb-4">
                      <div class="flex items-center gap-2">
                        <div class="w-2 h-2 rounded-full bg-accent-green"></div>
                        <span class="font-mono text-xs sm:text-sm">SSH Key Management</span>
                      </div>
                      <button
                        class="btn-ghost text-xs"
                        data-testid="manage-keys"
                        @click=${this.handleShowSSHKeyManager}
                      >
                        Manage Keys
                      </button>
                    </div>

                    <div class="space-y-3">
                      <div class="bg-dark-bg border border-dark-border rounded p-3">
                        <p class="text-dark-text-muted text-xs mb-2">
                          Generate SSH keys for browser-based authentication
                        </p>
                        <p class="text-dark-text-muted text-xs">
                          💡 SSH keys work in both browser and terminal
                        </p>
                      </div>

                      <button
                        class="btn-secondary w-full py-2.5 sm:py-3 text-sm sm:text-base"
                        data-testid="ssh-login"
                        @click=${this.handleSSHKeyAuth}
                        ?disabled=${this.loading}
                      >
                        ${this.loading?"Authenticating...":"Login with SSH Key"}
                      </button>
                    </div>
                  </div>
                `:""}
          </div>
        </div>
      </div>
    `}};_([$({type:Object})],xe.prototype,"authClient",2),_([A()],xe.prototype,"loading",2),_([A()],xe.prototype,"error",2),_([A()],xe.prototype,"success",2),_([A()],xe.prototype,"currentUserId",2),_([A()],xe.prototype,"loginPassword",2),_([A()],xe.prototype,"userAvatar",2),_([A()],xe.prototype,"authConfig",2),_([A()],xe.prototype,"isMobile",2),xe=_([z("auth-login")],xe);var de=class extends F{constructor(){super(...arguments);this.visible=!1;this.keys=[];this.loading=!1;this.error="";this.success="";this.showAddForm=!1;this.newKeyName="";this.newKeyPassword="";this.importKeyName="";this.importKeyContent="";this.showInstructions=!1;this.instructionsKeyId=""}createRenderRoot(){return this}connectedCallback(){super.connectedCallback(),this.refreshKeys()}refreshKeys(){this.keys=this.sshAgent.listKeys()}async handleGenerateKey(){if(!this.newKeyName.trim()){this.error="Please enter a key name";return}this.loading=!0,this.error="";try{let e=await this.sshAgent.generateKeyPair(this.newKeyName,this.newKeyPassword||void 0);this.downloadPrivateKey(e.privateKeyPEM,this.newKeyName),this.success=`SSH key "${this.newKeyName}" generated successfully. Private key downloaded.`,this.newKeyName="",this.newKeyPassword="",this.showAddForm=!1,this.showInstructions=!0,this.instructionsKeyId=e.keyId,this.refreshKeys(),console.log("Generated key ID:",e.keyId)}catch(e){this.error=`Failed to generate key: ${e}`}finally{this.loading=!1}}downloadPrivateKey(e,i){let s=new Blob([e],{type:"text/plain"}),o=URL.createObjectURL(s),c=document.createElement("a");c.href=o,c.download=`${i.replace(/\s+/g,"_")}_private.pem`,document.body.appendChild(c),c.click(),document.body.removeChild(c),URL.revokeObjectURL(o)}async handleImportKey(){if(!this.importKeyName.trim()||!this.importKeyContent.trim()){this.error="Please enter both key name and private key content";return}this.loading=!0,this.error="";try{let e=await this.sshAgent.addKey(this.importKeyName,this.importKeyContent);this.success=`SSH key "${this.importKeyName}" imported successfully`,this.importKeyName="",this.importKeyContent="",this.showAddForm=!1,this.refreshKeys(),console.log("Imported key ID:",e)}catch(e){this.error=`Failed to import key: ${e}`}finally{this.loading=!1}}handleClose(){this.dispatchEvent(new CustomEvent("close"))}handleRemoveKey(e,i){confirm(`Are you sure you want to remove the SSH key "${i}"?`)&&(this.sshAgent.removeKey(e),this.success=`SSH key "${i}" removed successfully`,this.refreshKeys())}handleDownloadPublicKey(e,i){let s=this.sshAgent.getPublicKey(e);if(s){let o=new Blob([s],{type:"text/plain"}),c=URL.createObjectURL(o),r=document.createElement("a");r.href=c,r.download=`${i.replace(/\s+/g,"_")}_public.pub`,document.body.appendChild(r),r.click(),document.body.removeChild(r),URL.revokeObjectURL(c)}}render(){return this.visible?S`
      <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div
          class="bg-dark-bg border border-dark-border rounded-lg p-6 w-full max-w-4xl max-h-[80vh] overflow-y-auto"
        >
          <div class="flex items-center justify-between mb-6">
            <h2 class="text-xl font-mono text-dark-text">SSH Key Manager</h2>
            <button @click=${this.handleClose} class="text-dark-text-muted hover:text-dark-text">
              ✕
            </button>
          </div>

          ${this.error?S`
                <div class="bg-status-error text-dark-bg px-4 py-2 rounded mb-4 font-mono text-sm">
                  ${this.error}
                  <button
                    @click=${()=>{this.error=""}}
                    class="ml-2 text-dark-bg hover:text-dark-text"
                  >
                    ✕
                  </button>
                </div>
              `:""}
          ${this.success?S`
                <div
                  class="bg-status-success text-dark-bg px-4 py-2 rounded mb-4 font-mono text-sm"
                >
                  ${this.success}
                  <button
                    @click=${()=>{this.success=""}}
                    class="ml-2 text-dark-bg hover:text-dark-text"
                  >
                    ✕
                  </button>
                </div>
              `:""}

          <div class="mb-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="font-mono text-lg text-dark-text">SSH Keys</h3>
              <button
                @click=${()=>{this.showAddForm=!this.showAddForm}}
                class="btn-primary"
                ?disabled=${this.loading}
              >
                ${this.showAddForm?"Cancel":"Add Key"}
              </button>
            </div>

            ${this.showAddForm?S`
                  <div class="space-y-6 mb-4">
                    <!-- Generate New Key Section -->
                    <div class="bg-dark-surface border border-dark-border rounded p-4">
                      <h4 class="text-dark-text font-mono text-lg mb-4 flex items-center gap-2">
                        🔑 Generate New SSH Key
                      </h4>

                      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                        <div>
                          <label class="form-label"
                            >Key Name <span class="text-accent-red">*</span></label
                          >
                          <input
                            type="text"
                            class="input-field"
                            placeholder="Enter name for new key"
                            .value=${this.newKeyName}
                            @input=${e=>{this.newKeyName=e.target.value}}
                            ?disabled=${this.loading}
                          />
                        </div>
                        <div>
                          <label class="form-label">Algorithm</label>
                          <div
                            class="input-field bg-dark-bg-secondary text-dark-text-muted cursor-not-allowed"
                          >
                            Ed25519 (recommended)
                          </div>
                        </div>
                      </div>

                      <div class="mb-4">
                        <label class="form-label">Password (Optional)</label>
                        <input
                          type="password"
                          class="input-field"
                          placeholder="Enter password to encrypt private key (optional)"
                          .value=${this.newKeyPassword}
                          @input=${e=>{this.newKeyPassword=e.target.value}}
                          ?disabled=${this.loading}
                        />
                        <p class="text-dark-text-muted text-xs mt-1">
                          💡 Leave empty for unencrypted key. Password is required when using the
                          key for signing.
                        </p>
                      </div>
                      <button
                        @click=${this.handleGenerateKey}
                        class="btn-primary"
                        ?disabled=${this.loading||!this.newKeyName.trim()}
                      >
                        ${this.loading?"Generating...":"Generate New Key"}
                      </button>
                    </div>

                    <!-- Import Existing Key Section -->
                    <div class="bg-dark-surface border border-dark-border rounded p-4">
                      <h4 class="text-dark-text font-mono text-lg mb-4 flex items-center gap-2">
                        📁 Import Existing SSH Key
                      </h4>

                      <div class="mb-4">
                        <label class="form-label"
                          >Key Name <span class="text-accent-red">*</span></label
                        >
                        <input
                          type="text"
                          class="input-field"
                          placeholder="Enter name for imported key"
                          .value=${this.importKeyName}
                          @input=${e=>{this.importKeyName=e.target.value}}
                          ?disabled=${this.loading}
                        />
                      </div>

                      <div class="mb-4">
                        <label class="form-label"
                          >Private Key (PEM format) <span class="text-accent-red">*</span></label
                        >
                        <textarea
                          class="input-field"
                          rows="6"
                          placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                          .value=${this.importKeyContent}
                          @input=${e=>{this.importKeyContent=e.target.value}}
                          ?disabled=${this.loading}
                        ></textarea>
                        <p class="text-dark-text-muted text-xs mt-1">
                          💡 If the key is password-protected, you'll be prompted for the password
                          when using it for authentication.
                        </p>
                      </div>

                      <button
                        @click=${this.handleImportKey}
                        class="btn-secondary"
                        ?disabled=${this.loading||!this.importKeyName.trim()||!this.importKeyContent.trim()}
                      >
                        ${this.loading?"Importing...":"Import Key"}
                      </button>
                    </div>
                  </div>
                `:""}
          </div>

          <!-- Instructions for new key -->
          ${this.showInstructions&&this.instructionsKeyId?S`
                <div class="bg-dark-surface border border-dark-border rounded p-4 mb-6">
                  <div class="flex items-center justify-between mb-4">
                    <h4 class="text-dark-text font-mono text-lg">Setup Instructions</h4>
                    <button
                      @click=${()=>{this.showInstructions=!1}}
                      class="text-dark-text-muted hover:text-dark-text"
                    >
                      ✕
                    </button>
                  </div>
                  <div class="space-y-4">
                    <div class="bg-dark-bg border border-dark-border rounded p-3">
                      <p class="text-dark-text-muted text-xs mb-2">
                        1. Add the public key to your authorized_keys file:
                      </p>
                      <div class="relative">
                        <pre
                          class="bg-dark-bg-secondary p-2 rounded text-xs overflow-x-auto text-dark-text pr-20"
                        >
echo "${this.sshAgent.getPublicKey(this.instructionsKeyId)}" >> ~/.ssh/authorized_keys</pre
                        >
                        <button
                          @click=${async()=>{let i=`echo "${this.sshAgent.getPublicKey(this.instructionsKeyId)}" >> ~/.ssh/authorized_keys`;await navigator.clipboard.writeText(i),this.success="Command copied to clipboard!"}}
                          class="absolute top-2 right-2 btn-ghost text-xs"
                          title="Copy command"
                        >
                          📋
                        </button>
                      </div>
                    </div>
                    <div class="bg-dark-bg border border-dark-border rounded p-3">
                      <p class="text-dark-text-muted text-xs mb-2">2. Or copy the public key:</p>
                      <div class="relative">
                        <pre
                          class="bg-dark-bg-secondary p-2 rounded text-xs overflow-x-auto text-dark-text pr-20"
                        >
${this.sshAgent.getPublicKey(this.instructionsKeyId)}</pre
                        >
                        <button
                          @click=${async()=>{let e=this.sshAgent.getPublicKey(this.instructionsKeyId);e&&(await navigator.clipboard.writeText(e),this.success="Public key copied to clipboard!")}}
                          class="absolute top-2 right-2 btn-ghost text-xs"
                          title="Copy to clipboard"
                        >
                          📋 Copy
                        </button>
                      </div>
                    </div>
                    <p class="text-dark-text-muted text-xs font-mono">
                      💡 Tip: Make sure ~/.ssh/authorized_keys has correct permissions (600)
                    </p>
                  </div>
                </div>
              `:""}

          <!-- Keys List -->
          <div class="space-y-4">
            ${this.keys.length===0?S`
                  <div class="text-center py-8 text-dark-text-muted">
                    <p class="font-mono text-lg mb-2">No SSH keys found</p>
                    <p class="text-sm">Generate or import a key to get started</p>
                  </div>
                `:this.keys.map(e=>S`
                    <div class="ssh-key-item">
                      <div class="flex items-start justify-between">
                        <div class="flex-1">
                          <div class="flex items-center gap-2 mb-2">
                            <h4 class="font-mono font-semibold text-dark-text">${e.name}</h4>
                            <span class="badge badge-ed25519">${e.algorithm}</span>
                            ${e.encrypted?S`<span class="badge badge-encrypted">🔒 Encrypted</span>`:""}
                          </div>
                          <div class="text-sm text-dark-text-muted font-mono space-y-1">
                            <div>ID: ${e.id}</div>
                            <div>Fingerprint: ${e.fingerprint}</div>
                            <div>Created: ${new Date(e.createdAt).toLocaleString()}</div>
                          </div>
                        </div>
                        <div class="flex gap-2">
                          <button
                            @click=${()=>this.handleDownloadPublicKey(e.id,e.name)}
                            class="btn-ghost text-xs"
                            title="Download Public Key"
                          >
                            📥 Public
                          </button>
                          <button
                            @click=${()=>this.handleRemoveKey(e.id,e.name)}
                            class="btn-ghost text-xs text-status-error hover:bg-status-error hover:text-dark-bg"
                            title="Remove Key"
                          >
                            🗑️
                          </button>
                        </div>
                      </div>
                    </div>
                  `)}
          </div>
        </div>
      </div>
    `:S``}};_([$({type:Object})],de.prototype,"sshAgent",2),_([$({type:Boolean})],de.prototype,"visible",2),_([A()],de.prototype,"keys",2),_([A()],de.prototype,"loading",2),_([A()],de.prototype,"error",2),_([A()],de.prototype,"success",2),_([A()],de.prototype,"showAddForm",2),_([A()],de.prototype,"newKeyName",2),_([A()],de.prototype,"newKeyPassword",2),_([A()],de.prototype,"importKeyName",2),_([A()],de.prototype,"importKeyContent",2),_([A()],de.prototype,"showInstructions",2),_([A()],de.prototype,"instructionsKeyId",2),de=_([z("ssh-key-manager")],de);Pe();var K=N("app"),ne=class extends F{constructor(){super(...arguments);this.errorMessage="";this.successMessage="";this.sessions=[];this.loading=!1;this.currentView="auth";this.selectedSessionId=null;this.hideExited=this.loadHideExitedState();this.showCreateModal=!1;this.showFileBrowser=!1;this.showSSHKeyManager=!1;this.showSettings=!1;this.isAuthenticated=!1;this.sidebarCollapsed=this.loadSidebarState();this.sidebarWidth=this.loadSidebarWidth();this.userInitiatedSessionChange=!1;this.isResizing=!1;this.mediaState=Ye.getCurrentState();this.showLogLink=!1;this.hasActiveOverlay=!1;this.initialLoadComplete=!1;this.responsiveObserverInitialized=!1;this.initialRenderComplete=!1;this.hotReloadWs=null;this.errorTimeoutId=null;this.successTimeoutId=null;this.autoRefreshIntervalId=null;this.resizeCleanupFunctions=[];this.handleKeyDown=e=>{(e.metaKey||e.ctrlKey)&&e.key==="o"&&this.currentView==="list"&&(e.preventDefault(),this.showFileBrowser=!0),e.key==="Escape"&&this.currentView==="session"&&!this.showFileBrowser&&!this.showCreateModal&&(e.preventDefault(),this.handleNavigateToList())};this.handleMobileOverlayClick=e=>{this.isInSidebarDismissMode&&(e.preventDefault(),e.stopPropagation(),this.handleToggleSidebar())};this.handleResizeStart=e=>{e.preventDefault(),this.isResizing=!0,this.cleanupResizeListeners(),document.addEventListener("mousemove",this.handleResize),document.addEventListener("mouseup",this.handleResizeEnd),this.resizeCleanupFunctions.push(()=>{document.removeEventListener("mousemove",this.handleResize),document.removeEventListener("mouseup",this.handleResizeEnd)}),document.body.style.cursor="ew-resize",document.body.style.userSelect="none"};this.handleResize=e=>{if(!this.isResizing)return;let i=Math.max(Ve.MIN_WIDTH,Math.min(Ve.MAX_WIDTH,e.clientX));this.sidebarWidth=i,this.saveSidebarWidth(i)};this.handleResizeEnd=()=>{this.isResizing=!1,this.cleanupResizeListeners()};this.handlePopState=e=>{this.parseUrlAndSetState().catch(i=>K.error("Error parsing URL:",i))};this.handleOpenSettings=()=>{K.log("\u{1F3AF} handleOpenSettings called in app.ts"),this.showSettings=!0};this.handleCloseSettings=()=>{this.showSettings=!1};this.handleOpenFileBrowser=()=>{this.showFileBrowser=!0};this.handleNotificationEnabled=e=>{let{success:i,reason:s}=e.detail;i?this.showSuccess("Notifications enabled successfully"):this.showError(`Failed to enable notifications: ${s||"Unknown error"}`)}}createRenderRoot(){return this}connectedCallback(){super.connectedCallback(),this.setupHotReload(),this.setupKeyboardShortcuts(),this.setupNotificationHandlers(),this.setupResponsiveObserver(),this.setupPreferences(),$s(),this.initializeApp()}firstUpdated(){Promise.resolve().then(()=>{this.initialRenderComplete=!0})}willUpdate(e){(e.has("showFileBrowser")||e.has("showCreateModal")||e.has("showSSHKeyManager")||e.has("showSettings"))&&(this.hasActiveOverlay=this.showFileBrowser||this.showCreateModal||this.showSSHKeyManager||this.showSettings)}disconnectedCallback(){super.disconnectedCallback(),this.hotReloadWs&&this.hotReloadWs.close(),window.removeEventListener("popstate",this.handlePopState),window.removeEventListener("keydown",this.handleKeyDown),this.autoRefreshIntervalId!==null&&(clearInterval(this.autoRefreshIntervalId),this.autoRefreshIntervalId=null),this.responsiveUnsubscribe&&this.responsiveUnsubscribe(),this.cleanupResizeListeners()}setupKeyboardShortcuts(){window.addEventListener("keydown",this.handleKeyDown)}async initializeApp(){await this.checkAuthenticationStatus(),this.setupRouting()}async checkAuthenticationStatus(){let e=!1;try{let i=await fetch("/api/auth/config");if(i.ok){let s=await i.json();if(K.log("\u{1F527} Auth config:",s),e=s.noAuth,s.noAuth){K.log("\u{1F513} No auth required, bypassing authentication"),this.isAuthenticated=!0,this.currentView="list",await this.initializeServices(e),await this.loadSessions(),this.startAutoRefresh();return}}}catch(i){K.warn("\u26A0\uFE0F Could not fetch auth config:",i)}this.isAuthenticated=j.isAuthenticated(),K.log("\u{1F510} Authentication status:",this.isAuthenticated),this.isAuthenticated?(this.currentView="list",await this.initializeServices(e),await this.loadSessions(),this.startAutoRefresh()):this.currentView="auth"}async handleAuthSuccess(){K.log("\u2705 Authentication successful"),this.isAuthenticated=!0,this.currentView="list",await this.initializeServices(!1),await this.loadSessions(),this.startAutoRefresh();let i=new URL(window.location.href).searchParams.get("session");if(i){let s=this.sessions.find(o=>o.id===i);if(s){this.userInitiatedSessionChange=!1,this.selectedSessionId=i,this.currentView="session";let o=s.name||s.command.join(" ");console.log("[App] Setting title from checkUrlParams:",o),document.title=`${o} - VibeTunnel`}}}async initializeServices(e=!1){K.log("\u{1F680} Initializing services...");try{await pi.initialize(),e?K.log("\u23ED\uFE0F Skipping push notification service initialization (no-auth mode)"):await ee.initialize(),K.log("\u2705 Services initialized successfully")}catch(i){K.error("\u274C Failed to initialize services:",i)}}async handleLogout(){K.log("\u{1F44B} Logging out"),await j.logout(),this.isAuthenticated=!1,this.currentView="auth",this.sessions=[]}handleShowSSHKeyManager(){this.showSSHKeyManager=!0}handleCloseSSHKeyManager(){this.showSSHKeyManager=!1}showError(e){this.errorTimeoutId!==null&&(clearTimeout(this.errorTimeoutId),this.errorTimeoutId=null),this.errorMessage=e,this.errorTimeoutId=window.setTimeout(()=>{this.errorMessage="",this.errorTimeoutId=null},je.ERROR_MESSAGE_TIMEOUT)}showSuccess(e){this.successTimeoutId!==null&&(clearTimeout(this.successTimeoutId),this.successTimeoutId=null),this.successMessage=e,this.successTimeoutId=window.setTimeout(()=>{this.successMessage="",this.successTimeoutId=null},je.SUCCESS_MESSAGE_TIMEOUT)}clearError(){this.errorTimeoutId===null&&(this.errorMessage="")}clearSuccess(){this.successTimeoutId!==null&&(clearTimeout(this.successTimeoutId),this.successTimeoutId=null),this.successMessage=""}async loadSessions(){this.initialLoadComplete||(this.loading=!0);let e=async()=>{try{let i=j.getAuthHeader(),s=await fetch("/api/sessions",{headers:i});if(s.ok){let o=await s.json(),c=o.filter(r=>r.activityStatus);if(c.length>0?K.debug("Sessions with activity status:",c.map(r=>({id:r.id,name:r.name,command:r.command,status:r.status,activityStatus:r.activityStatus}))):K.debug("No sessions have activity status"),this.sessions=o,this.clearError(),this.currentView==="list"){let r=this.sessions.length;document.title=`VibeTunnel - ${r} Session${r!==1?"s":""}`}if(this.selectedSessionId&&this.currentView==="session"&&!this.sessions.find(a=>a.id===this.selectedSessionId)){K.warn(`Selected session ${this.selectedSessionId} no longer exists, redirecting to dashboard`),this.selectedSessionId=null,this.currentView="list";let a=new URL(window.location.href);a.searchParams.delete("session"),window.history.replaceState({},"",a.toString())}}else if(s.status===401){this.handleLogout();return}else this.showError("Failed to load sessions")}catch(i){K.error("error loading sessions:",i),this.showError("Failed to load sessions")}finally{this.loading=!1,this.initialLoadComplete=!0}};if(!this.initialLoadComplete&&"startViewTransition"in document&&typeof document.startViewTransition=="function"){K.log("\u{1F3A8} Using View Transition API for initial session load"),document.body.classList.add("initial-session-load");let i=document.startViewTransition(async()=>{await e(),await this.updateComplete});i.ready.then(()=>{K.log("\u2728 Initial load view transition ready")}).catch(s=>{K.debug("View transition not supported or failed (this is normal):",s)}),i.finished.finally(()=>{K.log("\u2705 Initial load view transition finished"),document.body.classList.remove("initial-session-load")}).catch(()=>{document.body.classList.remove("initial-session-load")})}else this.initialLoadComplete?await e():(K.log("\u{1F3A8} Using CSS animation fallback for initial load"),document.body.classList.add("initial-session-load"),await e(),setTimeout(()=>{document.body.classList.remove("initial-session-load")},600))}startAutoRefresh(){this.autoRefreshIntervalId=window.setInterval(()=>{(this.currentView==="list"||this.currentView==="session")&&this.loadSessions()},je.AUTO_REFRESH_INTERVAL)}async handleSessionCreated(e){let i=e.detail.sessionId,s=e.detail.message;if(!i){this.showError("Session created but ID not found in response");return}if(document.body.classList.add("modal-closing"),this.showCreateModal=!1,setTimeout(()=>{document.body.classList.remove("modal-closing")},300),s?.includes("Terminal spawned successfully")){this.showSuccess("Terminal window opened successfully");return}await this.waitForSessionAndSwitch(i)}async waitForSessionAndSwitch(e){console.log("[App] waitForSessionAndSwitch called with:",e);let i=10,s=je.SESSION_SEARCH_DELAY;for(let o=0;o<i;o++){await this.loadSessions();let c=this.sessions.find(r=>r.id===e);if(c){await this.handleNavigateToSession(new CustomEvent("navigate-to-session",{detail:{sessionId:c.id}}));return}await new Promise(r=>window.setTimeout(r,s))}K.log("session not found after all attempts"),this.showError("Session created but could not be found. Please refresh.")}handleSessionKilled(e){K.log(`session ${e.detail} killed`),this.loadSessions()}handleRefresh(){this.loadSessions()}handleError(e){this.showError(e.detail)}async handleHideExitedChange(e){K.log("handleHideExitedChange",{currentHideExited:this.hideExited,newHideExited:e.detail});let i=this.hideExited,s=window.scrollY,o=document.documentElement.scrollHeight,c=window.innerHeight,r=s+c>=o-100;document.body.classList.add("sessions-animating"),K.log("Added sessions-animating class"),this.hideExited=e.detail,this.saveHideExitedState(this.hideExited),await this.updateComplete,K.log("Update complete, scheduling animation"),requestAnimationFrame(()=>{let a=i?"sessions-showing":"sessions-hiding";document.body.classList.add(a),K.log("Added animation class:",a);let g=document.querySelectorAll(".session-flex-responsive > session-card");K.log("Found session cards to animate:",g.length),r&&requestAnimationFrame(()=>{window.scrollTo({top:document.documentElement.scrollHeight-c,behavior:"instant"})}),setTimeout(()=>{document.body.classList.remove("sessions-animating","sessions-showing","sessions-hiding"),K.log("Cleaned up animation classes"),r&&window.scrollTo({top:document.documentElement.scrollHeight-c,behavior:"instant"})},300)})}handleCreateSession(){"startViewTransition"in document&&typeof document.startViewTransition=="function"?document.startViewTransition(()=>{this.showCreateModal=!0}):this.showCreateModal=!0}handleCreateModalClose(){"startViewTransition"in document&&typeof document.startViewTransition=="function"?(document.body.classList.add("modal-closing"),document.startViewTransition(()=>{this.showCreateModal=!1}).finished.finally(()=>{document.body.classList.remove("modal-closing")})):this.showCreateModal=!1}cleanupSessionViewStream(){let e=this.querySelector("session-view");e?.streamConnection&&(K.log("Cleaning up stream connection"),e.streamConnection.disconnect(),e.streamConnection=null)}async handleNavigateToSession(e){let{sessionId:i}=e.detail;if(console.log("[App] handleNavigateToSession called with:",i),this.selectedSessionId!==i&&this.cleanupSessionViewStream(),K.debug("Navigation to session:",{sessionId:i,windowWidth:window.innerWidth,mobileBreakpoint:Re.MOBILE,isMobile:this.mediaState.isMobile,currentSidebarCollapsed:this.sidebarCollapsed,mediaStateIsMobile:this.mediaState.isMobile}),this.userInitiatedSessionChange=!0,"startViewTransition"in document&&typeof document.startViewTransition=="function")K.debug("before transition - elements with view-transition-name:"),document.querySelectorAll('[style*="view-transition-name"]').forEach(o=>{K.debug("element:",o,"style:",o.getAttribute("style"))}),document.startViewTransition(async()=>{this.selectedSessionId=i,this.currentView="session",this.updateUrl(i);let o=this.sessions.find(c=>c.id===i);if(o){let c=o.name||o.command.join(" ");console.log("[App] Setting title from view transition:",c),document.title=`${c} - VibeTunnel`}else console.log("[App] No session found for view transition:",i);this.mediaState.isMobile&&(this.sidebarCollapsed=!0,this.saveSidebarState(!0)),await this.updateComplete,Oi(i,this),K.debug("after transition - elements with view-transition-name:"),document.querySelectorAll('[style*="view-transition-name"]').forEach(c=>{K.debug("element:",c,"style:",c.getAttribute("style"))})}).ready.then(()=>{K.debug("view transition ready")}).catch(o=>{K.error("view transition failed:",o)});else{this.selectedSessionId=i,this.currentView="session",this.updateUrl(i);let s=this.sessions.find(o=>o.id===i);if(s){let o=s.name||s.command.join(" ");console.log("[App] Setting title from fallback:",o),document.title=`${o} - VibeTunnel`}else console.log("[App] No session found for fallback:",i);this.mediaState.isMobile&&(this.sidebarCollapsed=!0,this.saveSidebarState(!0)),this.updateComplete.then(()=>{Oi(i,this)})}}handleNavigateToList(){this.cleanupSessionViewStream();let e=this.sessions.length;document.title=`VibeTunnel - ${e} Session${e!==1?"s":""}`,"startViewTransition"in document&&typeof document.startViewTransition=="function"?document.startViewTransition(()=>(this.selectedSessionId=null,this.currentView="list",this.updateUrl(),this.updateComplete)):(this.selectedSessionId=null,this.currentView="list",this.updateUrl())}async handleKillAll(){let e=this.querySelectorAll("session-card"),i=[];if(e.forEach(c=>{c.session&&c.session.status==="running"&&i.push(c.kill())}),i.length===0)return;let o=(await Promise.all(i)).filter(c=>c).length;o===i.length?this.showSuccess(`All ${o} sessions killed successfully`):o>0?this.showError(`Killed ${o} of ${i.length} sessions`):this.showError("Failed to kill sessions"),window.setTimeout(()=>{this.loadSessions()},je.KILL_ALL_ANIMATION_DELAY)}handleCleanExited(){let e=this.querySelector("session-list");e?.handleCleanupExited&&e.handleCleanupExited()}handleToggleSidebar(){this.sidebarCollapsed=!this.sidebarCollapsed,this.saveSidebarState(this.sidebarCollapsed)}handleSessionStatusChanged(e){K.log("Session status changed:",e.detail),this.loadSessions()}loadHideExitedState(){try{let e=localStorage.getItem("hideExitedSessions");return e!==null?e==="true":!0}catch(e){return K.error("error loading hideExited state:",e),!0}}saveHideExitedState(e){try{localStorage.setItem("hideExitedSessions",String(e))}catch(i){K.error("error saving hideExited state:",i)}}loadSidebarState(){try{let e=localStorage.getItem("sidebarCollapsed"),i=window.innerWidth<Re.MOBILE,s=i?e!==null?e==="true":!0:!1;return K.debug("Loading sidebar state:",{savedValue:e,windowWidth:window.innerWidth,mobileBreakpoint:Re.MOBILE,isMobile:i,forcedDesktopExpanded:!i,resultingState:s?"collapsed":"expanded"}),s}catch(e){return K.error("error loading sidebar state:",e),window.innerWidth<Re.MOBILE}}saveSidebarState(e){try{localStorage.setItem("sidebarCollapsed",String(e))}catch(i){K.error("error saving sidebar state:",i)}}loadSidebarWidth(){try{let e=localStorage.getItem("sidebarWidth"),i=e!==null?Number.parseInt(e,10):Ve.DEFAULT_WIDTH;return Math.max(Ve.MIN_WIDTH,Math.min(Ve.MAX_WIDTH,i))}catch(e){return K.error("error loading sidebar width:",e),Ve.DEFAULT_WIDTH}}saveSidebarWidth(e){try{localStorage.setItem("sidebarWidth",String(e))}catch(i){K.error("error saving sidebar width:",i)}}setupResponsiveObserver(){this.responsiveUnsubscribe=Ye.subscribe(e=>{let i=this.mediaState;this.mediaState=e,this.responsiveObserverInitialized&&this.initialRenderComplete?!i.isMobile&&e.isMobile&&!this.sidebarCollapsed&&(this.sidebarCollapsed=!0,this.saveSidebarState(!0)):this.responsiveObserverInitialized||(this.responsiveObserverInitialized=!0)})}cleanupResizeListeners(){this.resizeCleanupFunctions.forEach(e=>e()),this.resizeCleanupFunctions=[],document.body.style.cursor="",document.body.style.userSelect=""}setupRouting(){window.addEventListener("popstate",this.handlePopState.bind(this)),this.parseUrlAndSetState().catch(e=>K.error("Error parsing URL:",e))}async parseUrlAndSetState(){let i=new URL(window.location.href).searchParams.get("session");try{let s=await fetch("/api/auth/config");if(s.ok){if(!(await s.json()).noAuth){if(!j.isAuthenticated()){this.currentView="auth",this.selectedSessionId=null;return}}}else if(!j.isAuthenticated()){this.currentView="auth",this.selectedSessionId=null;return}}catch{if(!j.isAuthenticated()){this.currentView="auth",this.selectedSessionId=null;return}}if(i)if(this.sessions.length===0&&this.isAuthenticated&&await this.loadSessions(),this.sessions.find(o=>o.id===i))this.selectedSessionId=i,this.currentView="session";else{K.warn(`Session ${i} not found in sessions list`),this.selectedSessionId=null,this.currentView="list";let o=new URL(window.location.href);o.searchParams.delete("session"),window.history.replaceState({},"",o.toString())}else this.selectedSessionId=null,this.currentView="list"}updateUrl(e){let i=new URL(window.location.href);e?i.searchParams.set("session",e):i.searchParams.delete("session"),window.history.pushState(null,"",i.toString())}setupHotReload(){if(window.location.hostname==="localhost"||window.location.hostname==="127.0.0.1")try{let i=`${window.location.protocol==="https:"?"wss:":"ws:"}//${window.location.host}?hotReload=true`;this.hotReloadWs=new WebSocket(i),this.hotReloadWs.onmessage=s=>{JSON.parse(s.data).type==="reload"&&window.location.reload()}}catch(e){K.log("error setting up hot reload:",e)}}setupNotificationHandlers(){}setupPreferences(){try{let e=localStorage.getItem("vibetunnel_app_preferences");if(e){let i=JSON.parse(e);this.showLogLink=i.showLogLink||!1}}catch(e){K.error("Failed to load app preferences",e)}window.addEventListener("app-preferences-changed",e=>{let i=e;this.showLogLink=i.detail.showLogLink})}get showSplitView(){return this.currentView==="session"&&this.selectedSessionId!==null}get selectedSession(){return this.sessions.find(e=>e.id===this.selectedSessionId)}get sidebarClasses(){if(!this.showSplitView)return"w-full min-h-screen flex flex-col";let e="bg-dark-bg-secondary border-r border-dark-border flex flex-col",i=this.mediaState.isMobile,s=this.initialRenderComplete&&!i&&this.userInitiatedSessionChange?"sidebar-transition":"",o=i?"absolute left-0 top-0 bottom-0 z-30 flex":s,c=this.sidebarCollapsed?i?"hidden mobile-sessions-sidebar collapsed":"sm:w-0 sm:overflow-hidden sm:translate-x-0 flex":i?"overflow-visible sm:translate-x-0 flex mobile-sessions-sidebar expanded":"overflow-visible sm:translate-x-0 flex";return`${e} ${this.showSplitView?c:""} ${this.showSplitView?o:""}`}get sidebarStyles(){if(!this.showSplitView||this.sidebarCollapsed){let i=this.mediaState.isMobile;return this.showSplitView&&this.sidebarCollapsed&&!i?"width: 0px;":""}return this.mediaState.isMobile?`width: calc(100vw - ${Ve.MOBILE_RIGHT_MARGIN}px);`:`width: ${this.sidebarWidth}px;`}get shouldShowMobileOverlay(){return this.showSplitView&&!this.sidebarCollapsed&&this.mediaState.isMobile}get shouldShowResizeHandle(){return this.showSplitView&&!this.sidebarCollapsed&&!this.mediaState.isMobile}get mainContainerClasses(){return this.showSplitView?`flex h-screen overflow-hidden relative ${this.isIOS()?"ios-split-view":""}`:"min-h-screen"}isIOS(){return/iPad|iPhone|iPod/.test(navigator.userAgent)&&!("MSStream"in window)}get isInSidebarDismissMode(){return!this.mediaState.isMobile||!this.shouldShowMobileOverlay?!1:window.innerHeight>window.innerWidth}render(){let e=this.showSplitView,i=this.selectedSession;return S`
      <!-- Error notification overlay -->
      ${this.errorMessage?S`
            <div class="fixed top-4 right-4 z-50">
              <div
                class="bg-status-error text-dark-bg px-4 py-2 rounded shadow-lg font-mono text-sm"
              >
                ${this.errorMessage}
                <button
                  @click=${()=>{this.errorTimeoutId!==null&&(clearTimeout(this.errorTimeoutId),this.errorTimeoutId=null),this.errorMessage=""}}
                  class="ml-2 text-dark-bg hover:text-dark-text"
                >
                  ✕
                </button>
              </div>
            </div>
          `:""}
      ${this.successMessage?S`
            <div class="fixed top-4 right-4 z-50">
              <div
                class="bg-status-success text-dark-bg px-4 py-2 rounded shadow-lg font-mono text-sm"
              >
                ${this.successMessage}
                <button
                  @click=${()=>{this.successTimeoutId!==null&&(clearTimeout(this.successTimeoutId),this.successTimeoutId=null),this.successMessage=""}}
                  class="ml-2 text-dark-bg hover:text-dark-text"
                >
                  ✕
                </button>
              </div>
            </div>
          `:""}

      <!-- Main content -->
      ${this.currentView==="auth"?S`
            <auth-login
              .authClient=${j}
              @auth-success=${this.handleAuthSuccess}
              @show-ssh-key-manager=${this.handleShowSSHKeyManager}
              @open-settings=${this.handleOpenSettings}
            ></auth-login>
          `:S`
      <!-- Main content with split view support -->
      <div class="${this.mainContainerClasses}">
        <!-- Mobile overlay when sidebar is open -->
        ${this.shouldShowMobileOverlay?S`
              <div
                class="fixed inset-0 sm:hidden transition-all ${this.isInSidebarDismissMode?"bg-black bg-opacity-50 backdrop-blur-sm":"bg-transparent pointer-events-none"}"
                style="z-index: ${Ms.MOBILE_OVERLAY}; transition-duration: ${Bi.MOBILE_SLIDE}ms;"
                @click=${this.handleMobileOverlayClick}
              ></div>
            `:""}

        <!-- Sidebar with session list - always visible on desktop -->
        <div class="${this.sidebarClasses}" style="${this.sidebarStyles}">
          <app-header
            .sessions=${this.sessions}
            .hideExited=${this.hideExited}
            .showSplitView=${e}
            .currentUser=${j.getCurrentUser()?.userId||null}
            .authMethod=${j.getCurrentUser()?.authMethod||null}
            @create-session=${this.handleCreateSession}
            @hide-exited-change=${this.handleHideExitedChange}
            @kill-all-sessions=${this.handleKillAll}
            @clean-exited-sessions=${this.handleCleanExited}
            @open-file-browser=${this.handleOpenFileBrowser}
            @open-settings=${this.handleOpenSettings}
            @logout=${this.handleLogout}
            @navigate-to-list=${this.handleNavigateToList}
          ></app-header>
          <div class="${this.showSplitView?"flex-1 overflow-y-auto":"flex-1"} bg-dark-bg-secondary">
            <session-list
              .sessions=${this.sessions}
              .loading=${this.loading}
              .hideExited=${this.hideExited}
              .selectedSessionId=${this.selectedSessionId}
              .compactMode=${e}
              .authClient=${j}
              @session-killed=${this.handleSessionKilled}
              @refresh=${this.handleRefresh}
              @error=${this.handleError}
              @hide-exited-change=${this.handleHideExitedChange}
              @kill-all-sessions=${this.handleKillAll}
              @navigate-to-session=${this.handleNavigateToSession}
              @open-file-browser=${()=>{this.showFileBrowser=!0}}
            ></session-list>
          </div>
        </div>

        <!-- Resize handle for sidebar -->
        ${this.shouldShowResizeHandle?S`
              <div
                class="w-1 bg-dark-border hover:bg-accent-green cursor-ew-resize transition-colors ${this.isResizing?"bg-accent-green":""}"
                style="transition-duration: ${Bi.RESIZE_HANDLE}ms;"
                @mousedown=${this.handleResizeStart}
                title="Drag to resize sidebar"
              ></div>
            `:""}

        <!-- Main content area -->
        ${e?S`
              <div class="flex-1 relative sm:static transition-none">
                ${Ts(this.selectedSessionId,S`
                    <session-view
                      .session=${i}
                      .showBackButton=${!1}
                      .showSidebarToggle=${!0}
                      .sidebarCollapsed=${this.sidebarCollapsed}
                      .disableFocusManagement=${this.hasActiveOverlay}
                      @navigate-to-list=${this.handleNavigateToList}
                      @toggle-sidebar=${this.handleToggleSidebar}
                      @session-status-changed=${this.handleSessionStatusChanged}
                    ></session-view>
                  `)}
              </div>
            `:""}
      </div>
      `}

      <!-- File Browser Modal -->
      <file-browser
        .visible=${this.showFileBrowser}
        .mode=${"browse"}
        .session=${null}
        @browser-cancel=${()=>{this.showFileBrowser=!1}}
      ></file-browser>

      <!-- Unified Settings Modal -->
      <unified-settings
        .visible=${this.showSettings}
        @close=${this.handleCloseSettings}
        @notifications-enabled=${()=>this.showSuccess("Notifications enabled")}
        @notifications-disabled=${()=>this.showSuccess("Notifications disabled")}
        @success=${s=>this.showSuccess(s.detail)}
        @error=${s=>this.showError(s.detail)}
      ></unified-settings>

      <!-- SSH Key Manager Modal -->
      <ssh-key-manager
        .visible=${this.showSSHKeyManager}
        .sshAgent=${j.getSSHAgent()}
        @close=${this.handleCloseSSHKeyManager}
      ></ssh-key-manager>

      <!-- Session Create Modal -->
      <session-create-form
        .visible=${this.showCreateModal}
        .authClient=${j}
        @session-created=${this.handleSessionCreated}
        @cancel=${this.handleCreateModalClose}
        @error=${this.handleError}
      ></session-create-form>

      <!-- Version and logs link in bottom right -->
      ${this.showLogLink?S`
        <div class="fixed bottom-4 right-4 text-dark-text-muted text-xs font-mono z-20">
          <a href="/logs" class="hover:text-dark-text transition-colors">Logs</a>
          <span class="ml-2">v${Is}</span>
        </div>
      `:""}
    `}};_([A()],ne.prototype,"errorMessage",2),_([A()],ne.prototype,"successMessage",2),_([A()],ne.prototype,"sessions",2),_([A()],ne.prototype,"loading",2),_([A()],ne.prototype,"currentView",2),_([A()],ne.prototype,"selectedSessionId",2),_([A()],ne.prototype,"hideExited",2),_([A()],ne.prototype,"showCreateModal",2),_([A()],ne.prototype,"showFileBrowser",2),_([A()],ne.prototype,"showSSHKeyManager",2),_([A()],ne.prototype,"showSettings",2),_([A()],ne.prototype,"isAuthenticated",2),_([A()],ne.prototype,"sidebarCollapsed",2),_([A()],ne.prototype,"sidebarWidth",2),_([A()],ne.prototype,"userInitiatedSessionChange",2),_([A()],ne.prototype,"isResizing",2),_([A()],ne.prototype,"mediaState",2),_([A()],ne.prototype,"showLogLink",2),_([A()],ne.prototype,"hasActiveOverlay",2),ne=_([z("vibetunnel-app")],ne);Vt().catch(console.error);window.addEventListener("notification-action",h=>{let{action:t,data:e}=h.detail,i=document.querySelector("vibetunnel-app");i&&i.dispatchEvent(new CustomEvent("notification-action",{detail:{action:t,data:e}}))});
/*! Bundled license information:

@lit/reactive-element/css-tag.js:
  (**
   * @license
   * Copyright 2019 Google LLC
   * SPDX-License-Identifier: BSD-3-Clause
   *)

@lit/reactive-element/reactive-element.js:
lit-html/lit-html.js:
lit-element/lit-element.js:
@lit/reactive-element/decorators/custom-element.js:
@lit/reactive-element/decorators/property.js:
@lit/reactive-element/decorators/state.js:
@lit/reactive-element/decorators/event-options.js:
@lit/reactive-element/decorators/base.js:
@lit/reactive-element/decorators/query.js:
@lit/reactive-element/decorators/query-all.js:
@lit/reactive-element/decorators/query-async.js:
@lit/reactive-element/decorators/query-assigned-nodes.js:
lit-html/directive.js:
lit-html/async-directive.js:
lit-html/directives/repeat.js:
  (**
   * @license
   * Copyright 2017 Google LLC
   * SPDX-License-Identifier: BSD-3-Clause
   *)

lit-html/is-server.js:
  (**
   * @license
   * Copyright 2022 Google LLC
   * SPDX-License-Identifier: BSD-3-Clause
   *)

@lit/reactive-element/decorators/query-assigned-elements.js:
lit-html/directives/keyed.js:
  (**
   * @license
   * Copyright 2021 Google LLC
   * SPDX-License-Identifier: BSD-3-Clause
   *)

lit-html/directive-helpers.js:
lit-html/directives/ref.js:
  (**
   * @license
   * Copyright 2020 Google LLC
   * SPDX-License-Identifier: BSD-3-Clause
   *)
*/
