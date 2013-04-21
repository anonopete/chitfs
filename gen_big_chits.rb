#!/usr/bin/ruby

exit(1) unless (ARGV.size > 0)
num = ARGV.shift.to_i

def sys(x)
  puts x
  system(x)
end


sys("./keys chit localhost 1 1 SERVER chy0000")

0.upto(num).each do |i|
  to = sprintf("%04d",i)
  sys("./keys public yCLIENT#{to}")
end

sys("./keys derive chy0000 chz0000 public yCLIENT0000.pub")

1.upto(num).each do |i|
  from = sprintf("%04d",i-1)
  to = sprintf("%04d",i)
  sys("./keys derive chy#{from} chy#{to} label blather")
  sys("./keys derive chz#{from} chz#{to} delegate yCLIENT#{from}.pri yCLIENT#{to}.pub")
end

1.upto(9).each do |i|
  sys("rm chy*#{i}")
  sys("rm chz*#{i}")
end

sys("rm yCL*")

