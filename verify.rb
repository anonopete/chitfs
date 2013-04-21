#!/usr/bin/ruby

ys = Hash.new(0)
zs = Hash.new(0)
num = 1000

0.step(num,10).each do |i|
  0.step(9).each do |j|
    s = `keys verify SERVER chy#{sprintf("%04d", i)}`
    flds = s.split(/\s+/)
    ys[flds[1]] += flds[2].to_i
  end
end

ys.keys.sort.each do |k|
  print ys[k] / 10, " "
end
puts ""

0.step(num,10).each do |i|
  0.step(9).each do |j|
    s = `keys verify SERVER chz#{sprintf("%04d", i)}`
    flds = s.split(/\s+/)
    zs[flds[1]] += flds[2].to_i
  end
end

zs.keys.sort.each do |k|
  print zs[k] / 10, " "
end

puts ""
