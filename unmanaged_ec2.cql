// =====================================================================================================
// Newly launched EC2 instances with no Falcon sensor (near-live) - Falcon NG-SIEM / CQL
// Time range: Last 6 hours for an initial assessment; scheduled runs: window >= interval + grace + ~15m.
//             Instances older than the window: use unmanaged_ec2.py. Ended instances: unmanaged_ec2_ended.cql.
// Scale:      built for high-churn environments: groupBy/defineTable use limit=max and
//             table() uses its 200k row maximum.
//
// Instances = CloudTrail RunInstances in the window, minus any Stop/Terminate seen since
//             (CloudTrail ingest lag: median ~5s, p90 ~2.5min)
// Managed   = a Falcon Server sensor reported this instance_id via InstanceMetadata (AWS IMDS identity
//             doc). Sensors emit it ~40s after boot. KAC (event_platform=K8s) is ignored.
// Grace     = only flag instances running longer than ?grace_minutes (default 15; blank or * = 15), giving the sensor
//             time to install/check in and CloudTrail time to arrive.
// =====================================================================================================

// ---- Sensor side: instance_id -> Falcon server sensor ----------------------------------------------
defineTable(name="sensors", include=[instance_id, aid, ComputerName], query={
    #event_simpleName=InstanceMetadata InstanceMetadataProvider=4 event_platform!=K8s
    | regex("\"instanceId\"\\s*:\\s*\"(?<instance_id>i-[0-9a-f]+)\"", field=InstanceMetadata)
    | match(file="aid_master_main.csv", field=aid, include=[ProductType], strict=false)
    | in(field=ProductType, values=["3"])            // 3=Server. Add "2"=DC, "1"=Workstation if wanted
    | groupBy([instance_id], function=selectLast([aid, ComputerName]), limit=max)
})

// ---- Instance side: CloudTrail lifecycle -----------------------------------------------------------
| #repo=fcs_csp_events #Vendor=aws #event.outcome=success Vendor.eventName=/^(Run|Start|Stop|Terminate)Instances$/
| split(Vendor.responseElements.instancesSet.items)
| instance_id := Vendor.responseElements.instancesSet.items.instanceId
| case {
    Vendor.eventName=/^(Run|Start)Instances$/
        | state := "running"
        | launch_ms := Vendor.responseElements.instancesSet.items.launchTime
        | private_ip := Vendor.responseElements.instancesSet.items.privateIpAddress
        | platform := Vendor.responseElements.instancesSet.items.platform
        | type := Vendor.responseElements.instancesSet.items.instanceType
        // arn is omitted for cross-account callers (userIdentity.type=AWSAccount) -> fall back
        | launched_by := Vendor.userIdentity.arn
        | case {
            launched_by=*;
            Vendor.userIdentity.invokedBy=* | launched_by := Vendor.userIdentity.invokedBy;
            * | launched_by := format("cross-account %s (%s)", field=[Vendor.userIdentity.accountId, Vendor.userIdentity.principalId]);
          }
        | user_agent := Vendor.userAgent;
    * | state := "stopped/terminated";
  }
| account := Vendor.recipientAccountId | region := cloud.region   // recipient = account owning the instance
                                                                  // (cloud.account.id is the caller's account)

| groupBy([instance_id], limit=max, function=[
      selectLast([state]),
      max(launch_ms, as=launch_ms),
      collect([account, region, platform, type, private_ip, launched_by, user_agent])
  ])
| state="running" launch_ms=*

// ---- Grace period ---------------------------------------------------------------------------------
| running_min := (now() - launch_ms) / 60000
| grace := ?{grace_minutes="15"}
| case { grace=/^\d+(\.\d+)?$/; * | grace := 15 }     // UI sends "*" for an empty parameter box -> 15
| test(running_min > grace)

// ---- Unmanaged = no Falcon server sensor ----------------------------------------------------------
| match(table="sensors", field=instance_id, strict=false)
| aid!=*
| platform := if(platform=="windows", then="Windows", else="Linux/other")
| running_min := round(running_min)
| launch_time := formatTime("%Y-%m-%d %H:%M:%S", field=launch_ms, timezone="UTC")
| console_url := format("https://%s.console.aws.amazon.com/ec2/home?region=%s#InstanceDetails:instanceId=%s",
                        field=[region, region, instance_id])
| table([account, region, instance_id, platform, type, private_ip, launch_time, running_min, launched_by, user_agent, console_url],
        sortby=launch_time, order=desc, limit=200000)
