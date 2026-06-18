self.addEventListener('install',event=>self.skipWaiting());
self.addEventListener('push',event=>{const data=event.data?event.data.json():{title:'PrivMsg',body:'New encrypted message'}; event.waitUntil(self.registration.showNotification(data.title||'PrivMsg',{body:data.body||'New encrypted message'}));});
