# Task 6 - Follow the Data, Part 2
![Static Badge](https://img.shields.io/badge/Categories-Forensics%2C%20Databases%2C%20Exploitation-blue)
![Static Badge](https://img.shields.io/badge/Points-800-light_green)

> While you were working, we found the small U.S. cellular provider which issued the SIM card recovered from the device: Blue Horizon Mobile.
> 
> As advised by NSA legal counsel we reached out to notify them of a possible compromise and shared the IP address you discovered. Our analysts explained that sophisticated cyber threat actors may use co-opted servers to exfiltrate data and Blue Horizon Mobile confirmed that the IP address is for an old unused database server in their internal network. It was unmaintained and (unfortunately) reachable by any device in their network.
> 
> We believe the threat actor is using the server as a "dead drop", and it is the only lead we have to find them. Blue Horizon has agreed to give you limited access to this server on their internal network via an SSH "jumpbox". They will also be sure not to make any other changes that might tip off the actor. They have given you the authority to access the system, but unfortunately they could not find credentials. So you only have access to the database directly on TCP port 27017
> 
> Use information from the device firmware, and (below) SSH jumpbox location and credentials to login to the database via an SSH tunnel and discover the IP address of the system picking up a dead drop. Be patient as the actor probably only checks the dead drop periodically. Note the jumpbox IP is 100.127.0.2 so don't report yourself by mistake
> 
> Downloads:
> - SSH host key to authenticate the jumpbox (optional) ([jumpbox-ssh_host_ecdsa_key.pub](./downloads/jumpbox-ssh_host_ecdsa_key.pub))
> - SSH private key to authenticate to the jumpbox: user@external-support.bluehorizonmobile.com on TCP port 22 (jumpbox.key)
> ---
> Prompt:
> - Enter the IP address (don't guess)

## Solution
Using MongoDB information we found in Task 5, we can now connect to the server where the device is sending its exfiltration data. We'll first set up port forwarding on the jumpbox so that our local port `27017` is mapped to port `27017` on the exfiltration server located at `100.102.144.34`. We'll then adjust the connection string so that it uses our loopback address and connect through the jumpbox using `mongosh`.

```
ssh -i jumpbox.key -L 27017:100.102.144.34:27017 user@external-support.bluehorizonmobile.com
mongosh mongodb://maintenance:ed4faa4d05f294@127.0.0.1:27017/?authSource=snapshot-28c5e8e20fcc
```

Once we have a MongoDB shell, we can check which databases are present, switch to the only one available, and then check the collections. We find a collection named `files` that looks like it might be interesting.

```
test> show dbs
snapshot-28c5e8e20fcc  72.00 KiB
test> use snapshot-28c5e8e20fcc
switched to db snapshot-28c5e8e20fcc
snapshot-28c5e8e20fcc> show collections
files
```

We can search the `files` collection to see if there are any records, but it appears to be empty.

```
snapshot-28c5e8e20fcc> db.files.find({})
```

We can use the `insertOne` function to add our own record and then search the collection again to confirm it was inserted.

```
snapshot-28c5e8e20fcc> db.files.insertOne({test: "test"})
{
  acknowledged: true,
  insertedId: ObjectId('6597cf61e66f6520eaa3e652')
}
snapshot-28c5e8e20fcc> db.files.find({})
[ { _id: ObjectId('6597cf52e66f6520eaa3e652'), test: 'test' } ]
```

Waiting a minute or two and then checking the collection again reveals it's now empty. Knowing this, we can conclude that the threat actor is connecting to the database, retrieving any records, and then deleting thing. Now we need to find a way to get more information on their connection and find the originating IP address. Searching through the docs for potentially useful functionality will eventually lead us to the [db.setProfilingLevel function](https://www.mongodb.com/docs/manual/reference/method/db.setProfilingLevel/), but attempting to run this will give us a permissions error.

```
snapshot-28c5e8e20fcc> db.setProfilingLevel(2)
MongoServerError: not authorized on snapshot-28c5e8e20fcc to execute command { profile: 2, lsid: { id: UUID("333f4ec9-5cfe-42a5-86bb-fe7e99175a32") }, $db: "snapshot-28c5e8e20fcc" }
```

It's possible to check our own permissions using the command `db.getUser("maintenance")`.

```
snapshot-28c5e8e20fcc> db.getUser("maintenance")
{
  _id: 'snapshot-28c5e8e20fcc.maintenance',
  userId: UUID('1237a1f5-00ef-4712-9985-4317d865d417'),
  user: 'maintenance',
  db: 'snapshot-28c5e8e20fcc',
  roles: [
    { role: 'readWrite', db: 'snapshot-28c5e8e20fcc' },
    { role: 'userAdmin', db: 'snapshot-28c5e8e20fcc' }
  ],
  mechanisms: [ 'SCRAM-SHA-1', 'SCRAM-SHA-256' ]
}
```

Based on the above, we see we have the `userAdmin` role, which [according to the MongoDB docs](https://www.mongodb.com/docs/manual/reference/built-in-roles/), gives us the ability to grant additional roles. We can use this to elevate our privileges by granting ourselves the `dbAdmin` role.

```
snapshot-28c5e8e20fcc> db.grantRolesToUser("maintenance", [ { role: "dbAdmin", db: "snapshot-28c5e8e20fcc" } ])
{ ok: 1 }
snapshot-28c5e8e20fcc> db.getUser("maintenance")
{
  _id: 'snapshot-28c5e8e20fcc.maintenance',
  userId: UUID('1237a1f5-00ef-4712-9985-4317d865d417'),
  user: 'maintenance',
  db: 'snapshot-28c5e8e20fcc',
  roles: [
    { role: 'readWrite', db: 'snapshot-28c5e8e20fcc' },
    { role: 'userAdmin', db: 'snapshot-28c5e8e20fcc' },
    { role: 'dbAdmin', db: 'snapshot-28c5e8e20fcc' }
  ],
  mechanisms: [ 'SCRAM-SHA-1', 'SCRAM-SHA-256' ]
}
```

With our new permissions, it's now possible for us to adjust the profiling level of the database using the `db.setProfilingLevel()` function. Setting it to a value of either `1` or `2` will enable the profiler so that it collects additional details about any operations performed on the database. We'll set it to level `2` and then wait for the threat actor to connect again. We can then check the profiling output by searching the `system.profile` collection as shown below.

```
 db.setProfilingLevel(2)
 db.system.profile.find()
 [
 ...
    {
        op: 'query',
        ns: 'snapshot-28c5e8e20fcc.files',
        command: {
        find: 'files',
        filter: {},
        lsid: { id: UUID('bdb1d7dd-4a68-4d84-8f5f-e697007c4bfe') },
        '$db': 'snapshot-28c5e8e20fcc'
        },
        keysExamined: 0,
        docsExamined: 0,
        cursorExhausted: true,
        numYield: 0,
        nreturned: 0,
        queryHash: '17830885',
        queryFramework: 'classic',
        locks: {
        FeatureCompatibilityVersion: { acquireCount: { r: Long('1') } },
        Global: { acquireCount: { r: Long('1') } },
        Mutex: { acquireCount: { r: Long('1') } }
        },
        flowControl: {},
        responseLength: 116,
        protocol: 'op_msg',
        millis: 0,
        planSummary: 'COLLSCAN',
        execStats: {
        stage: 'COLLSCAN',
        nReturned: 0,
        executionTimeMillisEstimate: 0,
        works: 1,
        advanced: 0,
        needTime: 0,
        needYield: 0,
        saveState: 0,
        restoreState: 0,
        isEOF: 1,
        direction: 'forward',
        docsExamined: 0
        },
        ts: ISODate('2023-09-29T07:39:19.611Z'),
        client: '100.89.114.48',
        allUsers: [ { user: 'maintenance', db: 'snapshot-28c5e8e20fcc' } ],
        user: 'maintenance@snapshot-28c5e8e20fcc'
    }
]
```

Within the profiling output, we'll find the threat actor's query command for checking the `files` collection along with their IP address, `100.89.114.48`, listed in the `client` field.
