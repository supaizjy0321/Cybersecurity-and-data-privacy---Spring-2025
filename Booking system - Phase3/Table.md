# Table of Testing


| Page/Feature | Guest | Reserver | Adminstrator | Notes (Specs #) |
| :---         |     :---:      |     :---:      |     :---:      | :---:      |
| localhost:8000 |  |  |  |  |
| └─ View Booked resources | ✅  | ✅   | ✅  |  Meets Spec 8 (booked resources visible without login, but no user identity) |
| └─ Modify Booked resources | ❌  | ✅ (can only modify the one created by own)  | ✅ (can modify all the booked resources)  |  Meets Spec 4 (admin modify), partial Spec 6 (reserver can modify own) |
| /resources |  |  |  |
| └─ Create New resources | ⚠️ (guest can add without login) | ✅ | ✅ | 	 Conflict with Spec 4 (admin only) |
| /resources?id=1 |  |  |  |
| └─ Open resource with id=1 | ⚠️ (open a black resource form) | ✅ (can modify id=1 resource) | ✅ (can modify id=1 resource) | 	 Conflict with Spec 4 (admin only) |
| /reservation |  |  |  |
| └─ Create New reservation | ❌ (Unauthorized) | ✅(can only create with age 15+) | ✅(can only create with age 15+) | Matches Spec 6 (age restriction), not Match Spec 7 (hourly booking) |
| /reservation?id=1 |  |  |  |
| └─ Check specific reservation | ❌  | ⚠️(show "Create reservation" form, but the Reserver username part cannot work) | ⚠️(show "Create reservation" form, but the Reserver username part cannot work) | Partial Spec 4/6 (UI shows form, but form partially broken) |
| /login |  |  |  |
| └─ login successfully with Email and password | ❌  | ✅   | ✅  | Matches Spec 2 |
| /logout | redirect to main page | redirect to main page | redirect to main page | Matches Spec 1 (web access via browser) |
| /register |  |  |  |
| └─ register a new account | ✅  | ✅   | ✅  | Matches Spec 2 |
| /api/resources |  |  |  |
| └─ View the api of resources | ✅ (guest can also open it)  | ✅   | ✅  | Matches Spec 8 again (open access to view resources) |
| /api/resources/1 |  |  |  |
| └─ View the specific resource | ❌ (Unauthorized)  | ✅ (show JSON of id=1)   | ✅ (show JSON of id=1)  | Matches Spec 4 |
| /api/reservations |  |  |  |
| └─ View the reservations | ❌ (not found)  | ❌ (not found)  | ❌ (not found)  |
| /api/reservations/1 |  |  |  |
| └─ View the specific reservation | ⚠️ (show JSON all the reservations with id=1&id=2)  | ⚠️ (show JSON all the reservations with id=1&id=2)   | ⚠️ (show JSON all the reservations with id=1&id=2)  |
| /api/resources/2|  |  |  |
| └─ View the specific reservation | ❌ (not found)  | ❌ (not found)  | ❌ (not found) |
| /api/users |  |  |  |
| └─ View the api of users | ⚠️ (the JSON format with all the users' token, username and role) | ⚠️ (the JSON format with all the users' token, username and role)  | ✅ (the JSON format with all the users' token, username and role) | Privacy concern — possibly violates Spec 8 |
| /api/session |  |  |  |
| └─ View the api of users | ❌ (Unauthorized)  | ⚠️ (no session info, but show the user's own name and role)  | ⚠️ (no session info, but show the user's own name and role) | Matches Spec 3 (role tracking after login)
| └─ View the api of users | ❌ (Unauthorized)  | ⚠️ (no session info, but show the user's own name and role)  | ⚠️ (no session info, but show the user's own name and role) | Matches Spec 3 (role tracking after login) 
