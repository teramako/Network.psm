<#
    Network.psm1
#>
enum IP_Flag {
    IP; Mask; Network
}
class BitIPAddress : System.Net.IPAddress {
    [string[]] $Bits = @()
    [IP_Flag] $Flag
    [byte] $Range
    BitIPAddress([long] $newAddress) : base([long] $newAddress) {
        $this.SetBit()
        $this.Flag = [IP_Flag]::IP
    }
    BitIPAddress([byte[]] $address) : base([byte[]] $address) {
        $this.SetBit()
        $this.Flag = [IP_Flag]::IP
    }
    BitIPAddress([long] $newAddress, [IP_Flag] $flag) : base([long] $newAddress) {
        $this.SetBit()
        $this.Flag = $flag
    }
    BitIPAddress([byte[]] $address, [IP_Flag] $flag) : base([byte[]] $address) {
        $this.SetBit()
        $this.Flag = $flag
    }
    [void] SetBit() {
        $this.Bits = $this.GetAddressBytes() | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, "0") }
    }
    [BitIPAddress] SetRange([byte] $Range) {
        $this.Range = $Range
        return $this
    }
    [string[]] SplitBitByRange() {
        $bitStr = $this.Bits -join "."
        if ($this.Range -eq 32) {
            return @($bitStr, "")
        }
        $mod = $this.Range % 8
        $index = ($this.Range - $mod) / 8
        $length = 8 * $index + $index + $mod

        return @($bitStr.Substring(0, $length), $bitStr.Substring($length))
    }
    [string] ToDisplayString() {
        $ipAddr = $this.ToString()
        ($bitLeft, $bitRight) = $this.SplitBitByRange()
        $result = switch($this.Flag) {
            IP {
                $msg = "{0}{1,-22}{2}" -F $global:PSStyle.Foreground.Blue, $ipAddr, $global:PSStyle.Reset
                $bit = "{0}{1} {2}{3}" -F $global:PSStyle.Foreground.Yellow, $bitLeft, $bitRight, $global:PSStyle.Reset
                "{0} {1}" -f $msg, $bit
            }
            Mask {
                $msg = "{0}{1,-22}{2}" -F $global:PSStyle.Foreground.Blue, ("{0} = {1}" -f $ipAddr, $this.Range), $global:PSStyle.Reset
                $bit = "{0}{1} {2}{3}" -F $global:PSStyle.Foreground.Red, $bitLeft, $bitRight, $global:PSStyle.Reset
                "{0} {1}" -f $msg, $bit
            }
            Network {
                $msg = "{0}{1,-22}{2}" -F $global:PSStyle.Foreground.Blue, ("{0}/{1}" -f $ipAddr, $this.Range), $global:PSStyle.Reset
                $a1 = $this.GetAddressBytes()[0]
                $len = $(
                    if (($a1 -band 127) -eq $a1) { 1
                    } elseif (($a1 -band 191) -eq $a1) { 2
                    } elseif (($a1 -band 223) -eq $a1) { 3
                    } elseif (($a1 -band 239) -eq $a1) { 4
                    } else { 5 }
                )
                $bit = "{0}{1}{2}{3} {4}{5}" -f
                    $global:PSStyle.Foreground.Magenta,
                    $bitLeft.Substring(0, $len),
                    $global:PSStyle.Foreground.Yellow,
                    $bitLeft.Substring($len),
                    $bitRight,
                    $global:PSStyle.Reset;
                "{0} {1}" -f $msg, $bit
            }
        }
        return $result
    }
}
[Flags()] enum IP_Attributes {
    None = 0;
    Class_A = 1 -shl 0;
    Class_B = 1 -shl 1;
    Class_C = 1 -shl 2;
    Class_D = 1 -shl 3;
    Class_E = 1 -shl 4;
    Class_Invalid = 1 -shl 5;
    Loopback = 1 -shl 6;
    Private = 1 -shl 7;
    PtoP_Link = 1 -shl 8;
}
class CalcedIPAddress {
    static [uint64] $MAX = [Convert]::ToUint64("FFFFFFFF", 16)
    static [byte] ParseMask([string] $mask) {
        [byte] $Range = 32
        $res = $null
        if ([byte]::TryParse($mask, [ref]$res)) {
            $Range = $res
        } elseif ([ipaddress]::TryParse($mask, [ref]$res)) {
            $bit = ($res.GetAddressBytes() | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, "0") }) -join ""
            $Range = $bit.IndexOf("0")
        } else {
            throw ("Mask is must be 1 <= mask <= 32 or IPAddress: {0}" -f $mask)
        }
        if ($Range -ge 1 -and $Range -le 32) {
            return $Range
        }
        throw ("Mask is must be 1 <= mask <= 32: {0}" -f $res)
    }
    static [byte[]] RangeToBytes ([byte] $range) {
        $bit = ("1" * $range).PadRight(32, "0")
        $bytes = [byte[]]::new(4)
        for ($i = 0; $i -lt 4; $i++) {
            $bytes[$i] = [Convert]::ToByte($bit.Substring($i * 8, 8), 2)
        }
        return $bytes
    }
    [BitIPAddress] $IP
    [BitIPAddress] $Netmask
    [BitIPAddress] $Wildcard
    [BitIPAddress] $Network = $null
    [BitIPAddress] $HostMin = $null
    [BitIPAddress] $HostMax = $null
    [BitIPAddress] $Broadcast = $null
    [IP_Attributes] $Flags = [IP_Attributes]::None
    [byte] $MaskRange
    CalcedIPAddress ([ipaddress] $address, [byte] $range) {
        $this.IP = [BitIPAddress]::new($address.Address)
        $this.SetMask($range)
        $this.Calc()
    }
    CalcedIPAddress ([ipaddress] $address, [ipaddress] $mask) {
        $this.IP = [BitIPAddress]::new($address.Address)
        $this.SetMask($mask)
        $this.Calc()
    }
    [void] Calc() {
        $this.IP.SetRange($this.MaskRange)
        $this.Wildcard = [BitIPAddress]::new($this.Netmask.Address -bxor [CalcedIPAddress]::MAX).SetRange($this.MaskRange)
        $this.CalcFlags()

        if ($this.MaskRange -lt 31) {
            $this.Network = [BitIPAddress]::new($this.IP.Address -band $this.Netmask.Address, [IP_Flag]::Network).SetRange($this.MaskRange)
            $this.Broadcast = [BitIPAddress]::new($this.IP.Address -bor $this.Wildcard.Address).SetRange($this.MaskRange)
            $this.HostMin = [BitIPAddress]::new($this.Network.Address + 0x01000000).SetRange($this.MaskRange)
            $this.HostMax = [BitIPAddress]::new($this.Broadcast.Address - 0x01000000).SetRange($this.MaskRange)
        } elseif ($this.MaskRange -eq 31) {
            $this.Network = [BitIPAddress]::new($this.IP.Address -band $this.Netmask.Address, [IP_Flag]::Network).SetRange($this.MaskRange)
            $this.HostMin = [BitIPAddress]::new($this.Network.Address).SetRange($this.MaskRange)
            $this.HostMax = [BitIPAddress]::new($this.IP.Address -bor $this.Wildcard.Address).SetRange($this.MaskRange)
        }
    }
    [void] CalcFlags() {
        $ipBytes = $this.IP.GetAddressBytes()
        $a1 = $ipBytes[0]
        if (($a1 -band 127) -eq $a1) {
            $this.Flags = [IP_Attributes]::Class_A
            if ($a1 -eq 127) {
                $this.Flags += [IP_Attributes]::Loopback
            } elseif ($a1 -eq 10) {
                $this.Flags += [IP_Attributes]::Private
            }
        } elseif (($a1 -band 191) -eq $a1) {
            $this.Flags = [IP_Attributes]::Class_B
            if ($a1 -eq 172 -and ($ipBytes[1] -ge 16 -and $ipBytes[1] -le 31)) {
                $this.Flags += [IP_Attributes]::Private
            }
        } elseif (($a1 -band 223) -eq $a1) {
            $this.Flags = [IP_Attributes]::Class_C
            if ($a1 -eq 192 -and $ipBytes[1] -eq 168) {
                $this.Flags += [IP_Attributes]::Private
            }
        } elseif (($a1 -band 239) -eq $a1) {
            $this.Flags = [IP_Attributes]::Class_D
        } elseif (($a1 -band 247) -eq $a1) {
            $this.Flags = [IP_Attributes]::Class_E
        } else {
            $this.Flags = [IP_Attributes]::Class_Invalid
        }
        if ($this.MaskRange -eq 31) {
            $this.Flags += [IP_Attributes]::PtoP_Link
        }

    }
    [void] SetMask([byte] $range) {
        $this.MaskRange = $Range
        $this.Netmask = [BitIPAddress]::new([CalcedIPAddress]::RangeToBytes($range), [IP_Flag]::Mask).SetRange($Range)
    }
    [void] SetMask([ipaddress] $mask) {
        $this.Netmask = [BitIPAddress]::new($mask.Address, [IP_Flag]::Mask)
        $bit = ($mask.GetAddressBytes() | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, "0") }) -join ""
        $index = $bit.IndexOf("0")
        if ($index -gt 0) {
            $this.MaskRange = $index
        } else {
            $this.MaskRange = 32
        }
        $this.Netmask.SetRange($this.MaskRange)
    }
}
function Get-CalcIP {
    <#
        .SYNOPSIS
        An IPv4 Netmask/broadcast/etc calculator

        .DESCRIPTION
        Inspired by Linux 'ipcalc' command

        .PARAMETER IP
        IP(v4) address

        .PARAMETER Mask
        Subnet mask
        1 <= number <= 32 or IPAddress (ex. 255.255.255.0)

        .INPUTS
        IPAddress

        .EXAMPLE
        PS> Get-CalcIP 192.168.10.20 24

        Calculate 192.168.10.20/24 addres
        ```
        IP        : 192.168.10.20          11000000.10101000.00001010. 00010100
        Netmask   : 255.255.255.0 = 24     11111111.11111111.11111111. 00000000
        Wildcard  : 0.0.0.255              00000000.00000000.00000000. 11111111
        Network   : 192.168.10.0/24        11000000.10101000.00001010. 00000000
        HostMin   : 192.168.10.1           11000000.10101000.00001010. 00000001
        HostMax   : 192.168.10.254         11000000.10101000.00001010. 11111110
        Broadcast : 192.168.10.255         11000000.10101000.00001010. 11111111
        Flags     : Class_C, Private
        ```

        .EXAMPLE
        PS> "127.0.0.1", "192.168.20.10" | Get-CalcIP -Mask 20

        Calculate two of addresses
        ```
        IP        : 127.0.0.1              01111111.00000000.0000 0000.00000001
        Netmask   : 255.255.240.0 = 20     11111111.11111111.1111 0000.00000000
        Wildcard  : 0.0.15.255             00000000.00000000.0000 1111.11111111
        Network   : 127.0.0.0/20           01111111.00000000.0000 0000.00000000
        HostMin   : 127.0.0.1              01111111.00000000.0000 0000.00000001
        HostMax   : 127.0.15.254           01111111.00000000.0000 1111.11111110
        Broadcast : 127.0.15.255           01111111.00000000.0000 1111.11111111
        Flags     : Class_A, Loopback

        IP        : 192.168.20.10          11000000.10101000.0001 0100.00001010
        Netmask   : 255.255.240.0 = 20     11111111.11111111.1111 0000.00000000
        Wildcard  : 0.0.15.255             00000000.00000000.0000 1111.11111111
        Network   : 192.168.16.0/20        11000000.10101000.0001 0000.00000000
        HostMin   : 192.168.16.1           11000000.10101000.0001 0000.00000001
        HostMax   : 192.168.31.254         11000000.10101000.0001 1111.11111110
        Broadcast : 192.168.31.255         11000000.10101000.0001 1111.11111111
        Flags     : Class_C, Private
        ```
    #>
    [CmdletBinding()]
    [OutputType([CalcedIPAddress])]
    param(
        [Parameter(Mandatory, Position=0, ValueFromPipeline)]
        [Alias("Address")]
        [ipaddress] $IP,
        [Parameter(Position=1)]
        [ValidateScript({ ($_ -match "\d+\.\d+\.\d+\.\d+") -or ($_ -match "\d+" -and $_ -ge 1 -and $_ -le 32) })]
        [string] $Mask = 24
    )
    begin {
        $ErrorActionPreference = "stop"
        [byte] $Range = [CalcedIPAddress]::ParseMask($Mask)
    }
    process {
        "Arguments: {0} {1}" -f $IP, $Range | Write-Verbose
        $ipCalc = [CalcedIPAddress]::new($IP, $Range)
        return $ipCalc
    }
}
Set-Alias ipcalc Get-CalcIP
