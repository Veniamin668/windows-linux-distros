# 1. Ждем, пока фоновый msiexec создаст папку и файл (таймаут 30 сек)
$exePath = "C:\Program Files\TightVNC\tvnserver.exe"
$timeout = 30
while (!(Test-Path $exePath) -and $timeout -gt 0) {
    Start-Sleep -Seconds 1
    $timeout--
}

if (!(Test-Path $exePath)) {
    Write-Error "TightVNC не успел установиться в фоне за 30 секунд!"
    exit 1
}

# 2. Открываем фаервол намертво для Tailscale
netsh advfirewall firewall add rule name="TightVNC-Force" dir=in action=allow protocol=TCP localport=5900 profile=any

# 3. Скрипт автоматизации интерфейса UIAutomation
$uiScript = {
    Add-Type -AssemblyName ItemProvider, WindowsBase, PresentationFramework
    Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
    
    # Открываем основное окно TightVNC Overview
    Start-Process "C:\Program Files\TightVNC\tvnserver.exe"
    Start-Sleep -Seconds 3
    
    $ae = [System.Windows.Automation.AutomationElement]::RootElement
    $condition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "TightVNC Server - Overview")
    $overviewWindow = $ae.FindFirst([System.Windows.Automation.TreeScope]::Children, $condition)
    
    if ($overviewWindow) {
        # Кликаем по первой кнопке "Control Center..."
        $btnCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
        $buttons = $overviewWindow.FindAll([System.Windows.Automation.TreeScope]::Descendants, $btnCondition)
        foreach ($btn in $buttons) {
            if ($btn.Current.Name -eq "Control Center...") {
                $btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
                break
            }
        }
        Start-Sleep -Seconds 3
        
        # Ищем окно "TightVNC Server - Control Center (System Service)"
        $ccCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "TightVNC Server - Control Center (System Service)")
        $ccWindow = $ae.FindFirst([System.Windows.Automation.TreeScope]::Children, $ccCondition)
        
        if ($ccWindow) {
            # Кликаем "Configuration..."
            $configBtnCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "Configuration...")
            $configBtn = $ccWindow.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $configBtnCondition)
            $configBtn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
            Start-Sleep -Seconds 3
            
            # Ищем окно "TightVNC Service Configuration"
            $configCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "TightVNC Service Configuration")
            $configWindow = $ae.FindFirst([System.Windows.Automation.TreeScope]::Children, $configCondition)
            
            if ($configWindow) {
                # Переключаемся на вкладку "Authentication"
                $tabCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::TabItem)
                $tabs = $configWindow.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tabCondition)
                foreach ($tab in $tabs) {
                    if ($tab.Current.Name -eq "Authentication") {
                        $tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
                        break
                    }
                }
                Start-Sleep -Seconds 1
                
                # Находим и прожимаем чекбокс "Allow connections without a password"
                $chkCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "Allow connections without a password")
                $checkBox = $configWindow.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $chkCondition)
                
                # Проверяем, не прожата ли она уже, и переключаем
                $togglePattern = $checkBox.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
                if ($togglePattern.Current.ToggleState -eq 'Off') {
                    $togglePattern.Toggle()
                }
                Start-Sleep -Seconds 1
                
                # Жмем "OK"
                $okCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "OK")
                $okBtn = $configWindow.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $okCondition)
                $okBtn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
                
                # Закрываем оставшиеся окна, чтобы процессы не висели
                Start-Sleep -Seconds 1
                $ccWindow.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
                $overviewWindow.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
            }
        }
    }
}

# 4. Запускаем UI-кликер асинхронно в фоне текущей сессии раннера
Start-Job -ScriptBlock $uiScript | Wait-Job -Timeout 30

# 5. Передергиваем службу, чтобы применить изменения и поднять порт
Restart-Service -Name "tvnserver" -Force
