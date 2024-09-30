New-NetFirewallRule -DisplayName Display_Testing_Testing -Description Description_Testing_Testing -Group Group1_Testing_Testing -Enabled False -Profile Any -Direction Outbound -Action Allow -LocalAddress 1.1.1.1
New-NetFirewallRule -DisplayName Display_Testing_Testing -Description Description_Testing_Testing -Group Group1_Testing_Testing -Enabled True -Profile Any -Direction Outbound -Action Allow -LocalAddress 1.1.1.1
New-NetFirewallRule -DisplayName Display_Testing_Testing -Description Description_Testing_Testing -Group Group1_Testing_Testing -Enabled False -Profile Any -Direction Outbound -Action Allow -LocalAddress 1.1.1.1
New-NetFirewallRule -DisplayName Display_Testing_Testing -Description Description_Testing_Testing -Group Group1_Testing_Testing -Enabled True -Profile Any -Direction Outbound -Action Allow -LocalAddress 1.1.1.1
New-NetFirewallRule -DisplayName Display_Testing_Testing -Description Description_Testing_Testing -Group Group1_Testing_Testing -Enabled False -Profile Any -Direction Outbound -Action Allow -LocalAddress 1.1.1.1

New-NetFirewallRule -DisplayName Display_Testing_Testing -Description Description_Testing_Testing -Group Group1_Testing_Testing -Enabled True -Profile Any -Direction Inbound -Action Allow -LocalAddress 1.1.1.1
New-NetFirewallRule -DisplayName Display_Testing_Testing -Description Description_Testing_Testing -Group Group1_Testing_Testing -Enabled False -Profile Any -Direction Inbound -Action Allow -LocalAddress 1.1.1.1
New-NetFirewallRule -DisplayName Display_Testing_Testing -Description Description_Testing_Testing -Group Group1_Testing_Testing -Enabled True -Profile Any -Direction Inbound -Action Allow -LocalAddress 1.1.1.1
New-NetFirewallRule -DisplayName Display_Testing_Testing -Description Description_Testing_Testing -Group Group1_Testing_Testing -Enabled False -Profile Any -Direction Inbound -Action Allow -LocalAddress 1.1.1.1
New-NetFirewallRule -DisplayName Display_Testing_Testing -Description Description_Testing_Testing -Group Group1_Testing_Testing -Enabled True -Profile Any -Direction Inbound -Action Allow -LocalAddress 1.1.1.1

# note DisplayName == "Name" in our COM API
# Name must be unique - but is not accessible from the COM API - when you don't supply it, we default to a new GUID
