# logbook-verifier
TBD


## Usage

```
python3 ./logbook-verifier.py  --keyfile ../../thumbnail.key.json  --logbook  /Users/iuliana/Downloads/watch-logbook\ \(3\).json 
logbook-verifier 1.1 - Frankenwatch logbook signature and file hash verification utility
[✅] 2025-06-19 06:59:19:event id#1 (property: brand, model): signature valid
[✅] 2025-06-19 06:59:19:event id#2 (property: country): signature valid
[✅] 2025-06-19 06:59:57:event id#3 (image: dial): signature valid
     [✅] Download image: OK. File hash: OK.
[✅] 2025-06-19 07:00:13:event id#4 (image: back): signature valid
     [✅] Download image: OK. File hash: OK.
[✅] 2025-06-19 07:00:40:event id#5 (image: side-left): signature valid
....
[✅] 2025-08-12 13:17:15:event id#316 (image: dial): signature valid
     [✅] Download image: OK. File hash: OK.
[✅] 2025-08-12 13:17:16:event id#317 (thumbnail: dial): signature valid
     [✅] Download image: OK. File hash: OK.

============================================================
LOGBOOK VERIFICATION ANALYSIS SUMMARY
============================================================

📊 EVENT STATISTICS:
   Total events processed: 25
   Property updates: 8
   File uploads (images/thumbnails): 17

📝 PROPERTY UPDATE BREAKDOWN:
   brand: 1 update
   case_material: 1 update
   country: 1 update
   date_serviced: 3 updates
   model: 1 update
   note: 3 updates
   reference_number: 1 update
   wristband_type: 1 update

📁 FILE UPLOAD BREAKDOWN:
   image:back: 1 upload
   image:dial: 10 uploads
   image:movement: 1 upload
   image:note_image: 1 upload
   image:side-left: 1 upload
   thumbnail:dial: 3 uploads

⏰ TIME ANALYSIS:
   Oldest event: 2025-06-19 06:59:19 (54 days ago)
   Newest event: 2025-08-12 13:17:16 (0 days ago)
   Activity span: 54 days
   Active days: 4 days (days with events)
   Activity rate: 7.3% (percentage of days with events)

✅ VERIFICATION RESULTS:
   Passed: 25 events (cryptographic signatures verified)
   Failed: 0 events (invalid signatures - possible tampering)
   Warnings: 0 items (file downloads skipped/failed)

🎯 OVERALL STATUS:
   ✅ ALL EVENTS VERIFIED SUCCESSFULLY
   🔒 Logbook integrity confirmed - all signatures valid
============================================================

```
