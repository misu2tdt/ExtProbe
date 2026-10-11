# Spot check (10 rows, random.Random(7) over the 81 reviewed rows)

Check each row by hand against the package and trace; mark agree / disagree.

| ext_id | kind | proposed label | FN group | code evidence | trace evidence | agree? |
|---|---|---|---|---|---|---|
| lnajjhohknhgemncbaomjjjpmpdigedg | FN | malicious-likely | A | scripts/background.js:386 `f (result?.success && result?.infoURL) {       chrome.tabs.create({ url: result.infoURL` | POST to mines.cloudapi.stream/user_info answered {success:true, infoURL:""}; install tab cloudapi.stream -> julia-info.k | |
| gidejehfgombmkfflghejpncblgfkagj | TP | grey/PUP |  | app.js:607 `products",null,v),null}}async sendFeedbackProductSimilar(v){}async sendStoreTracker(v,b){const k=`https://` | merchant-page URLs to an execute-api endpoint (cashback tracking) | |
| cdpiopekjeonfjeocbfebemgocjciepp | FN | grey/PUP | C | background.js:12 `e.tabs.create({ url: 'https://cloudapi.stream/install/?reason=' + details.reason + '&id=' + chrome.runt` | install tab cloudapi.stream -> julia-info.kiev.ua (Cloudflare challenge); uninstall URL on cloudapi.stream | |
| ckneindgfbjnbbiggcmnjeofelhflhaj | TP | grey/PUP |  | assets/chunk-95ad446b.js:60 `;e.src="https://onlineapp.pro/paywall/".concat(this.paywallId,"?v=2"),e.id="paywall-".concat(thi` | hidden onlineapp.pro paywall IFRAME inserted on the declared target site; welcome/uninstall tabs on vendor site; no data | |
| dbclhjpifdfkofnmjfpheiondafpkoed | TP | grey/PUP |  | assets/chunk-rUGuHa_z.js:32 `;e.src="https://onlineapp.pro/paywall/".concat(this.paywallId,"?v=2"),e.id="paywall-".concat(thi` | hidden onlineapp.pro paywall IFRAME inserted on the declared target site; welcome/uninstall tabs on vendor site; no data | |
| maeccdadgnadblfddcmanhpofobhgfme | FN | malicious-likely | A | background.js:29 `f (result?.success && result?.infoURL) {       chrome.tabs.create({ url: result.infoURL` | POST to mines.cloudapi.stream/user_info answered {success:true, infoURL:""}; install tab cloudapi.stream -> julia-info.k | |
| egjidjbpglichdcondbcbdnbeeppgdph | TP | benign-looking |  | 2176.js:1 `();yield O.A.post(`${T.W2}/v2/devices/fingerprint`,{identifier:S,bundle:h.RL,sr:_.O0}).then(({data:` | device registration + node list on trustwallet.com gateways; Amplitude | |
| emedckhdnioeieppmeojgegjfkhdlaeo | FN | benign-looking | C | assets/background.js:2 `guments)},Et={PAGE_NAME:"data-alooma-page-name",DISABLED:"data-alooma-disabled",ELEMEN` | install/pin analytics to kra18.com | |
| coplmfnphahpcknbchcehdikbdieognn | TP | grey/PUP |  | sw.js:1 `is,"travelSites"),i.set(this,"travelSiteVisited"),o.set(this,"TravelArrow"),this.url="",!e)throw ` | base64 events with visited merchant URLs to api.travelarrow.io (merchant list 930 kB) | |
| pndmbpnfolikhfnfnkmjkkpcgkmaibec | FN | benign-looking | C | index.html:32 `port: <a href='mailto:support@aiadgenerator.app'>support@aiadgenerator.app</a>       </p>   </div` | welcome tab (DNS error) | |
