# Quick script to create a URL rewrite rule for the Proxy Not Shell vulnerability
# Source: https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/
# Started here: https://gist.github.com/jonade/1e8918044e720021cf3ca8c0a79eb6b1

# No warranties, expressed written or implied
# Use at your own risk

$name = 'Proxy Not Shell Rewrite'
$site = 'IIS:\Sites\Default Web Site'
$root = 'system.webServer/rewrite/rules'
$filter = "{0}/rule[@name='{1}']" -f $root, $name

Add-WebConfigurationProperty -PSPath $site -filter $root -name '.' -value @{name=$name; patternSyntax='Regular Expressions'; stopProcessing='True'}
Set-WebConfigurationProperty -PSPath $site -filter "$filter/match" -name 'url' -value ".*"
Set-WebConfigurationProperty -PSPath $site -filter "$filter/conditions" -name '.' -value @{input='{REQUEST_URI}'; matchType='0'; pattern='.*autodiscover\.json.*\@.*Powershell.*'; ignoreCase='True'; negate='False'}
Set-WebConfigurationProperty -PSPath $site -filter "$filter/action" -name '.' -value @{type='CustomResponse'}

