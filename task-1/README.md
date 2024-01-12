# Task 1 - Find the Unknown Object
![Static Badge](https://img.shields.io/badge/Categories-General%20Programming%2C%20Database%20Retrieval-blue)
![Static Badge](https://img.shields.io/badge/Points-10-light_green)

> The US Coast Guard (USCG) recorded an unregistered signal over 30 nautical miles away from the continental US (OCONUS). NSA is contacted to see if we have a record of a similar signal in our databases. The Coast guard provides a copy of the signal data. Your job is to provide the USCG any colluding records from NSA databases that could hint at the object’s location. Per instructions from the USCG, to raise the likelihood of discovering the source of the signal, they need multiple corresponding entries from the NSA database whose geographic coordinates are within 1/100th of a degree. Additionally, record timestamps should be no greater than 10 minutes apart.
> 
> Downloads:
> - file provided by the USCG that contains metadata about the unknown signal ([USCG.log](./downloads/USCG.log))
> - NSA database of signals ([database.db](./downloads/database.db))
> ---
> Prompt:
> - Provide database record IDs, one per line, that fit within the parameters specified above.

## Solution
We're provided with a JSON file (`USCG.log`) and an SQLite database (`database.db`). The JSON file contains location and timestamp data, and we're asked to find database entries that fall within specific bounds around that data (1/100th of a degree for the location and 10 minutes for the timestamp).

After opening the database in SQLite by using the command `sqlite database.db`, we can print the table names using `.tables` which reveals `location` and `timestamp` tables that each contain information we'll need to compare against our given data. It's possible to get additional information on the column names and data types for each table using the commands `PRAGMA table_info(location)` and `PRAGMA table_info(timestamp)`.

Adding and subtracting 0.01 from both the latitude and longitude within the JSON file will give us the location bounds. We can then search the database for matching entries using those bounds with the following query.
```sql
SELECT id FROM location WHERE CAST(latitude AS FLOAT) BETWEEN 29.22489 AND 29.24489 AND CAST(longitude AS FLOAT) BETWEEN -87.82918 AND -87.80918
``` 
This returns only two IDs (`277` and `379`), so it's possible to manually check their timestamps to verify they're within the mandatory 10 minute bound. These timestamps can be queried using using the following.
```sql
SELECT recDate, recTime FROM timestamp WHERE id=277 OR id=379
``` 
Both were found to be within the bounds and were submitted as the solution.

The `solve.py` solution script attempts to automate this process by using a more complex query that joins the `location` and `timestamp` tables to find IDs that fulfill all the constraints.
