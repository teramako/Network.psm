<#
    .SYNOPSIS
    Like PowerShell Core 7, define $PSStyle variable
#>
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $private:ESC = [char]0x1b
    $global:PSStyle = @{
        Reset = $ESC + '[0m'
        Foreground = @{
            Black =         $ESC + '[30m'
            BrightBlack =   $ESC + '[90m'
            White =         $ESC + '[37m'
            BrightWhite =   $ESC + '[97m'
            Red =           $ESC + '[31m'
            BrightRed =     $ESC + '[91m'
            Magenta =       $ESC + '[35m'
            BrightMagenta = $ESC + '[95m'
            Blue =          $ESC + '[34m'
            BrightBlue  =   $ESC + '[94m'
            Cyan =          $ESC + '[36m'
            BrightCyan  =   $ESC + '[96m'
            Green =         $ESC + '[32m'
            BrightGreen  =  $ESC + '[92m'
            Yellow =        $ESC + '[33m'
            BrightYellow =  $ESC + '[93m'
        }
        Background = @{
            Black =         $ESC + '[40m'
            BrightBlack =   $ESC + '[100m'
            White =         $ESC + '[47m'
            BrightWhite =   $ESC + '[107m'
            Red =           $ESC + '[41m'
            BrightRed =     $ESC + '[101m'
            Magenta =       $ESC + '[45m'
            BrightMagenta = $ESC + '[105m'
            Blue =          $ESC + '[44m'
            BrightBlue  =   $ESC + '[104m'
            Cyan =          $ESC + '[46m'
            BrightCyan  =   $ESC + '[106m'
            Green =         $ESC + '[42m'
            BrightGreen  =  $ESC + '[102m'
            Yellow =        $ESC + '[43m'
            BrightYellow =  $ESC + '[103m'
        }
    }
}
