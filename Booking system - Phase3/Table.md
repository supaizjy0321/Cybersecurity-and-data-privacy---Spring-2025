# Table of Testing


| Page/Feature | Guest | Reserver | Adminstrator |
| :---         |     :---:      |     :---:      |     :---:      |
| localhost:8000 |  |  |  |
| └─ View Booked resources | ✅  | ✅   | ✅  |
| └─ Modify Booked resources | ❌  | ✅ (can only modify the one created by own)  | ✅ (can modify all the booked resources)  |
| /resources |  |  |  |
| └─ Create New resources | ⚠️ (guest can add without login) | ✅ | ✅ |
| /resources?id=1 |  |  |  |
| └─ Open resource with id=1 | ⚠️ (open a black resource form) | ✅ (can modify id=1 resource) | ✅ (can modify id=1 resource) |
| /reservation |  |  |  |
| └─ Create New reservation | ❌ (Unauthorized) | ✅(can only create with age 15+) | ✅(can only create with age 15+) |
| /reservation?id=1 |  |  |  |
| └─ Check specific reservation | ❌  | ⚠️(show "Create reservation" form, but the Reserver username part cannot work) | ⚠️(show "Create reservation" form, but the Reserver username part cannot work) |
| /login |  |  |  |
| └─ login successfully with Email and password | ❌  | ✅   | ✅  |
| /logout | redirect to main page | redirect to main page | redirect to main page |
| /register |  |  |  |
| └─ register a new account | ✅  | ✅   | ✅  |
| /api/resources |  |  |  |
| └─ View the api of resources | ✅ (guest can also open it)  | ✅   | ✅  |
| /api/resources/1 |  |  |  |
| └─ View the specific resource | ❌ (Unauthorized)  | ✅ (show JSON of id=1)   | ✅ (show JSON of id=1)  |
| /api/reservations |  |  |  |
| └─ View the resources | ❌ (not found)  | ❌ (not found)  | ❌ (not found)  |
| /api/reservations/1 |  |  |  |
| └─ View the specific reservation | ⚠️ (show JSON all the reservations with id=1&id=2)  | ⚠️ (show JSON all the reservations with id=1&id=2)   | ⚠️ (show JSON all the reservations with id=1&id=2)  |
| /api/resources/2|  |  |  |
| └─ View the specific reservation | ❌ (not found)  | ❌ (not found)  | ❌ (not found) |
| /api/users |  |  |  |
| └─ View the api of users | ⚠️ (the JSON format with all the users' token, username and role) | ⚠️ (the JSON format with all the users' token, username and role)  | ✅ (the JSON format with all the users' token, username and role) |
| /api/session |  |  |  |
| └─ View the api of users | ❌ (Unauthorized)  | ⚠️ (no session info, but show the user's own name and role)  | ⚠️ (no session info, but show the user's own name and role) |
