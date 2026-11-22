// AVN-SYSTEME-2026 — secure staff account API for Vercel
// Required server-only env vars: SUPABASE_URL, SUPABASE_ANON_KEY,
// SUPABASE_SERVICE_ROLE_KEY, AVN_SCHOOL_ID.
const ALLOWED_ROLES = ['Administrateur','Direction','Secrétariat','Enseignant','Finance / Économat'];
const LOGIN_DOMAIN = 'login.avn.invalid';
const ALLOWED_PERMISSIONS = new Set(['dashboard','direction','recherche','archive','eleves','professeurs','classes','matieres','notes','absences','pointage','finances','comptabilite','creances','paie','bulletin','badge','releve','notifications','anniversaires','documents','anglais','virtuel','annees','sauvegarde','utilisateurs']);
const ORIGINS = new Set(['https://avn-systeme-2026-final.vercel.app','null']);
const env = () => {
  const e={url:(process.env.SUPABASE_URL||'').replace(/\/$/,''),anon:process.env.SUPABASE_ANON_KEY||'',service:process.env.SUPABASE_SERVICE_ROLE_KEY||'',school:process.env.AVN_SCHOOL_ID||''};
  if(!e.url||!e.anon||!e.service||!e.school) throw new Error('Configuration serveur AVN incomplète.');
  return e;
};
const json=(res,status,data)=>res.status(status).json(data);
const emailFor=u=>`${String(u||'').trim().toLowerCase()}@${LOGIN_DOMAIN}`;
const cleanPerms=p=>Array.isArray(p)?[...new Set(p.filter(x=>ALLOWED_PERMISSIONS.has(x)))]:[];
async function sb(e,path,{method='GET',body,token,admin=false}={}){
  const headers={'apikey':admin?e.service:e.anon,'Authorization':`Bearer ${admin?e.service:(token||e.anon)}`,'Content-Type':'application/json'};
  if(body!==undefined)headers.Prefer='return=representation';
  const r=await fetch(`${e.url}${path}`,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
  const t=await r.text();let d;try{d=t?JSON.parse(t):null}catch{d=null;}
  if(!r.ok){const err=new Error(d?.message||d?.msg||d?.error_description||'Erreur Supabase.');err.status=r.status;throw err;}
  return d;
}
async function authUser(e,token){return sb(e,'/auth/v1/user',{token});}
async function requireAdmin(e,token){
  if(!token)throw Object.assign(new Error('Connexion administrateur requise.'),{status:401});
  const user=await authUser(e,token);const id=user?.id;if(!id)throw Object.assign(new Error('Session invalide.'),{status:401});
  const q=`?school_id=eq.${encodeURIComponent(e.school)}&user_id=eq.${encodeURIComponent(id)}&active=eq.true&select=role,active`;
  const members=await sb(e,`/rest/v1/school_members${q}`,{admin:true});
  const profiles=await sb(e,`/rest/v1/avn_user_profiles?id=eq.${encodeURIComponent(id)}&active=eq.true&select=role,active`,{admin:true});
  if(!members?.some(x=>x.role==='Administrateur')||!profiles?.some(x=>x.role==='Administrateur'))throw Object.assign(new Error('Aksè rezève pou administratè aktif.'),{status:403});
  return user;
}
async function listAuthUsers(e){let all=[],page=1;for(;page<=20;page++){const d=await sb(e,`/auth/v1/admin/users?page=${page}&per_page=100`,{admin:true});const a=d?.users||[];all.push(...a);if(a.length<100)break;}return all;}
module.exports=async function handler(req,res){
  const origin=req.headers.origin||'';
  if(ORIGINS.has(origin)){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');}
  res.setHeader('Access-Control-Allow-Headers','authorization,content-type');res.setHeader('Access-Control-Allow-Methods','POST,GET,OPTIONS');
  if(req.method==='OPTIONS')return res.status(204).end();
  if(!['POST','GET'].includes(req.method))return json(res,405,{error:'Méthode non autorisée.'});
  try{
    const e=env();const body=req.method==='GET'?{}:(req.body||{});const action=body.action||req.query?.action;
    if(action==='login'){
      const username=String(body.username||'').trim().toLowerCase(),password=String(body.password||'');
      if(!/^[a-z0-9._-]{3,40}$/.test(username)||password.length<1)return json(res,400,{error:'Identifiant ou mot de passe invalide.'});
      let session;try{session=await sb(e,'/auth/v1/token?grant_type=password',{method:'POST',body:{email:emailFor(username),password}})}catch{return json(res,401,{error:'Identifiant ou mot de passe incorrect.'});}
      const uid=session?.user?.id;if(!uid)return json(res,401,{error:'Connexion impossible.'});
      const members=await sb(e,`/rest/v1/school_members?school_id=eq.${encodeURIComponent(e.school)}&user_id=eq.${encodeURIComponent(uid)}&active=eq.true&select=role,active`,{admin:true});
      const profiles=await sb(e,`/rest/v1/avn_user_profiles?id=eq.${encodeURIComponent(uid)}&active=eq.true&select=full_name,role,active`,{admin:true});
      const m=members?.[0],p=profiles?.[0];if(!m||!p||m.role!==p.role||!ALLOWED_ROLES.includes(m.role)){try{await sb(e,'/auth/v1/logout',{method:'POST',token:session.access_token});}catch{}return json(res,403,{error:'Compte AVN inactif ou non autorisé.'});}
      const meta=session.user.app_metadata||{};return json(res,200,{ok:true,session,member:{id:uid,username,name:p.full_name||username,role:m.role,teacherId:String(meta.avn_teacher_id||''),permissions:cleanPerms(meta.avn_permissions)}});
    }
    const token=String(req.headers.authorization||'').replace(/^Bearer\s+/i,'');
    await requireAdmin(e,token);
    if(action==='list'){
      const [members,profiles,authUsers]=await Promise.all([
        sb(e,`/rest/v1/school_members?school_id=eq.${encodeURIComponent(e.school)}&select=user_id,role,active,created_at`,{admin:true}),
        sb(e,'/rest/v1/avn_user_profiles?select=id,full_name,role,active,created_at',{admin:true}),listAuthUsers(e)
      ]);
      const amap=new Map(authUsers.map(u=>[u.id,u]));const pmap=new Map(profiles.map(p=>[p.id,p]));
      const users=(members||[]).map(m=>{const a=amap.get(m.user_id),p=pmap.get(m.user_id),meta=a?.app_metadata||{};return {id:m.user_id,username:String(a?.email||'').split('@')[0],name:p?.full_name||a?.user_metadata?.full_name||'',role:m.role,active:m.active===true&&p?.active===true,permissions:cleanPerms(meta.avn_permissions),teacherId:String(meta.avn_teacher_id||''),authProvider:'supabase'};}).filter(u=>u.username);
      return json(res,200,{ok:true,users});
    }
    if(action==='create'){
      const name=String(body.name||'').trim(),username=String(body.username||'').trim().toLowerCase(),password=String(body.password||''),role=String(body.role||'');
      const permissions=cleanPerms(body.permissions);const teacherId=String(body.teacherId||'').trim();
      if(role==='Enseignant'&&!/^[A-Za-z0-9_-]{1,100}$/.test(teacherId))return json(res,400,{error:'Une fiche professeur AVN doit être associée au compte Enseignant.'});
      if(role!=='Enseignant'&&teacherId)return json(res,400,{error:'La liaison professeur est réservée au rôle Enseignant.'});
      if(name.length<2||name.length>120||!/^[a-z0-9._-]{3,40}$/.test(username)||password.length<8||!ALLOWED_ROLES.includes(role))return json(res,400,{error:'Vérifiez le nom, l’identifiant, le rôle et le mot de passe (8 caractères minimum).'});
      if(role==='Administrateur')return json(res,403,{error:'La création d’un second administrateur doit être autorisée séparément.'});
      if(!permissions.length)return json(res,400,{error:'Chwazi omwen yon otorizasyon.'});
      const email=emailFor(username);const existing=await sb(e,`/auth/v1/admin/users?per_page=100&page=1`,{admin:true});
      if((existing?.users||[]).some(u=>String(u.email||'').toLowerCase()===email))return json(res,409,{error:'Cet identifiant existe déjà.'});
      const created=await sb(e,'/auth/v1/admin/users',{method:'POST',admin:true,body:{email,password,email_confirm:true,user_metadata:{full_name:name,avn_username:username},app_metadata:{avn_permissions:permissions,...(role==='Enseignant'?{avn_teacher_id:teacherId}:{})}}});
      const id=created?.user?.id||created?.id;if(!id)throw new Error('Supabase n’a pas retourné l’identifiant du compte.');
      try{
        await sb(e,'/rest/v1/avn_user_profiles',{method:'POST',admin:true,body:{id,full_name:name,role,active:true}});
        await sb(e,'/rest/v1/school_members',{method:'POST',admin:true,body:{school_id:e.school,user_id:id,role,active:true}});
      }catch(err){try{await sb(e,`/auth/v1/admin/users/${id}`,{method:'DELETE',admin:true});}catch{}throw err;}
      return json(res,201,{ok:true,id,username,name,role,teacherId,permissions});
    }
    if(action==='update'){
      const id=String(body.id||''),role=body.role?String(body.role):null,active=typeof body.active==='boolean'?body.active:null,password=body.password==null?null:String(body.password),permissions=body.permissions==null?null:cleanPerms(body.permissions),teacherId=body.teacherId==null?null:String(body.teacherId).trim();
      if(!/^[0-9a-f-]{36}$/i.test(id))return json(res,400,{error:'Identifiant de compte invalide.'});
      if(role&&!ALLOWED_ROLES.includes(role))return json(res,400,{error:'Rôle non autorisé.'});
      if(role==='Administrateur')return json(res,403,{error:'Chanjman wòl Administrateur pa otorize nan API sa a.'});
      if(teacherId!==null&&teacherId!==''&&!/^[A-Za-z0-9_-]{1,100}$/.test(teacherId))return json(res,400,{error:'Fiche professeur invalide.'});
      if(teacherId!==null&&teacherId!==''&&(role||'')!=='Enseignant')return json(res,400,{error:'La liaison professeur exige le rôle Enseignant.'});
      if(password!==null&&password.length<8)return json(res,400,{error:'Le mot de passe doit contenir au moins 8 caractères.'});
      const current=await sb(e,`/rest/v1/school_members?school_id=eq.${encodeURIComponent(e.school)}&user_id=eq.${encodeURIComponent(id)}&select=user_id,role,active`,{admin:true});
      if(!current?.length)return json(res,404,{error:'Compte AVN introuvable.'});
      const me=await authUser(e,token);if(id===me.id&&active===false)return json(res,400,{error:'Ou pa ka dezaktive pwòp kont ou.'});
      if(active===false&&current[0].role==='Administrateur')return json(res,403,{error:'Pa ka dezaktive administratè sa a atravè API an.'});
      const patch={};if(role)patch.role=role;if(active!==null)patch.active=active;
      if(Object.keys(patch).length){await sb(e,`/rest/v1/school_members?school_id=eq.${encodeURIComponent(e.school)}&user_id=eq.${encodeURIComponent(id)}`,{method:'PATCH',admin:true,body:patch});await sb(e,`/rest/v1/avn_user_profiles?id=eq.${encodeURIComponent(id)}`,{method:'PATCH',admin:true,body:{...patch}});}
      if(password!==null||permissions!==null||teacherId!==null){const authPatch={};if(password!==null)authPatch.password=password;const authMeta={};if(permissions!==null)authMeta.avn_permissions=permissions;if(teacherId!==null)authMeta.avn_teacher_id=teacherId;if(Object.keys(authMeta).length)authPatch.app_metadata=authMeta;await sb(e,`/auth/v1/admin/users/${id}`,{method:'PUT',admin:true,body:authPatch});}
      return json(res,200,{ok:true,id,role:role||current[0].role,active:active===null?current[0].active:active});
    }
    return json(res,400,{error:'Action AVN inconnue.'});
  }catch(err){console.error('AVN users API:',err.message);return json(res,err.status||500,{error:err.status?err.message:'Erreur serveur AVN. Vérifiez la configuration et les journaux Vercel.'});}
};
