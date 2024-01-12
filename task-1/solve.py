#!/usr/bin/env python3

import calendar
import json
import sqlite3
import time

# Load the JSON data from the USCG log
with open("./downloads/USCG.log") as infile:
    signal = json.loads(infile.read())

# Extract and format the location and timestamp information
lat = float(signal["coordinates"][0]["latitude"])
long = float(signal["coordinates"][0]["longitude"])
epoch = calendar.timegm(time.strptime(signal["timestamp"], "%m/%d/%Y, %H:%M:%S"))

# Calculate the upper and lower bounds on the coordinates and time as specified in the task description
deg_bound = 1/100
lat_low = lat - deg_bound
lat_high = lat + deg_bound
long_low = long - deg_bound
long_high = long + deg_bound
time_bound = 10 * 60

# Construct the query which finds IDs that are within both the coordinate and time bounds
query = f'''
SELECT location.id FROM location JOIN timestamp on location.id=timestamp.id
WHERE CAST(latitude AS FLOAT) BETWEEN {lat_low} AND {lat_high} 
AND CAST(longitude AS FLOAT) BETWEEN {long_low} AND {long_high}
AND ABS(STRFTIME('%s', CONCAT(SUBSTR(recDate,7), '-', SUBSTR(recDate,1,2), '-', SUBSTR(recDate,4,2), ' ', recTime)) - {epoch}) <= {time_bound}
'''

# Connect to the database and execute the query
con = sqlite3.connect("./downloads/database.db")
cur = con.cursor()
res = cur.execute(query)

for result in res.fetchall():
    print(result[0])
