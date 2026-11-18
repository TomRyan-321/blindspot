// =====================================================================================================
// Short-lived EC2 instances that ran with no Falcon sensor and have since stopped or terminated
// Falcon NG-SIEM / CQL. Companion to unmanaged_ec2.cql, which reports only instances still running.
//
// Time range: covers instances whose launch AND stop/terminate both fall inside the window.
//             Scheduled: window >= run interval + the longest lifetime you want to catch.
//
// Instances = CloudTrail RunInstances/StartInstances in the window whose latest event is
//             StopInstances or TerminateInstances (lifetime = end - launch)
// Managed   = a Falcon Server sensor reported this instance_id via InstanceMetadata (same logic as
//             unmanaged_ec2.cql). KAC (event_platform=K8s) is ignored.
// Filter    = ?min_lifetime_minutes (default 5; blank or * = 5). Instances that end sooner are
//             usually failed launches or ended before a sensor could check in. Set 0 to see all.
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
        | launched_by := Vendor.userIdentity.arn
        | case {
            launched_by=*;
            Vendor.userIdentity.invokedBy=* | launched_by := Vendor.userIdentity.invokedBy;
            * | launched_by := format("cross-account %s (%s)", field=[Vendor.userIdentity.accountId, Vendor.userIdentity.principalId]);
          }
        | user_agent := Vendor.userAgent;
    *
        | state := "ended"
        | end_ms := @timestamp
        | ended_how := if(Vendor.eventName=="TerminateInstances", then="terminated", else="stopped")
        | ended_by := Vendor.userIdentity.arn
        | case {
            ended_by=*;
            Vendor.userIdentity.invokedBy=* | ended_by := Vendor.userIdentity.invokedBy;
            * | ended_by := format("cross-account %s (%s)", field=[Vendor.userIdentity.accountId, Vendor.userIdentity.principalId]);
          };
  }
| account := Vendor.recipientAccountId | region := cloud.region   // recipient = account owning the instance

| groupBy([instance_id], limit=max, function=[
      selectLast([state]),
      max(launch_ms, as=launch_ms),
      max(end_ms, as=end_ms),
      collect([account, region, platform, type, private_ip, launched_by, user_agent, ended_how, ended_by])
  ])
| state="ended" launch_ms=* end_ms=*
| test(end_ms > launch_ms)

// ---- Lifetime filter ------------------------------------------------------------------------------
| lifetime_min := (end_ms - launch_ms) / 60000
| min_life := ?{min_lifetime_minutes="5"}
| case { min_life=/^\d+(\.\d+)?$/; * | min_life := 5 }  // UI sends "*" for an empty parameter box -> 5
| test(lifetime_min >= min_life)

// ---- Unmanaged = no Falcon server sensor ever reported this instance ------------------------------
| match(table="sensors", field=instance_id, strict=false)
| aid!=*
| platform := if(platform=="windows", then="Windows", else="Linux/other")
| lifetime_min := round(lifetime_min)
| launch_time := formatTime("%Y-%m-%d %H:%M:%S", field=launch_ms, timezone="UTC")
| end_time := formatTime("%Y-%m-%d %H:%M:%S", field=end_ms, timezone="UTC")
| table([account, region, instance_id, platform, type, private_ip, launch_time, end_time, lifetime_min,
         ended_how, launched_by, ended_by, user_agent],
        sortby=end_time, order=desc, limit=200000)
