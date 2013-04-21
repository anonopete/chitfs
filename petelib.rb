#!/usr/bin/ruby
require "stringio"
require 'tempfile'
require "cgi"
require 'date'
require "dbi"
require "gchart"

# table-prints both arrays and hashes
def parr(a)
  puts '<table border=1>'
  if (a.class == Array)
    a.each_with_index {|x,y| puts "<tr><th>#{y}</th><td>#{x}</td>"}
  elsif (a.class == Hash)
    a.each {|k,v| puts "<tr><th>#{k}</th><td>#{v}</td>"}
  end
  puts '<table border=1>'
end
    

# gives a hash w/ keys only for non-zero length, handles StringIO objects
def getForm()
  if not $cgi_pete_form
    cgi = CGI.new
    $form_cookies = cgi.cookies
    $cgi_pete_form = cgi2hash(cgi)
    end
  return $cgi_pete_form
end


def cgi2hash(cgi)
  h = {}
  cgi.keys.each do |x| 
    if (cgi[x].length > 0) 
      h[x] = case cgi[x]
             when StringIO
               cgi[x].read
             when Tempfile
               cgi[x].read
             else 
               cgi[x]
             end
    end
  end
  h
end

def prettyHash(h)
  print "\n<table border=1 cellpadding=5>\n"
  h.keys.each {|k| print "<tr><th>#{k}:</th><td>#{h[k].to_s}</td><td>#{h[k].class}</td><td>#{h[k].length}</td>\n"}
  print "</table>\n\n"
end

def makeSelect (name, onchange, selected, *l)
  s = "<SELECT name='#{name}' #{onchange ? "onchange='#{onchange}'" : ''}>\n"
  l.each do |choice|
    s += "\t<OPTION #{choice == selected ? 'SELECTED' : ''} VALUE=\"#{choice}\">#{choice}</OPTION>\n"
  end
  s += "</SELECT>\n"
end

def makeBox(name, onclick, checked, str)
  "<input name=#{name} #{onclick ? "onclick=\'return #{onclick}\'" : ''} type=checkbox #{checked.to_s}> #{str}"
end

#=============================================================================
  
# parse incomplete strings, returns ISO string

  
def parseDate(dtstr, backwards=nil)
  d = parseDateObj(dtstr, backwards)
  if d
    return d.to_s
  else
    return d
  end
end


# nums must start at the beginning of the string, possibly w/ preceding whitespace
def parseDateObj(dtstr, backwards=nil)
  if !(dtstr =~ /^\s*(\d+)(-|\/)?(\d+)?(-|\/)?(\d+)?/)
    x = ($dtstr =~ /(\d+)/)
    return nil
  end

  n1 = $1.to_i
  n3 = $3.to_i
  n5 = $5.to_i

  if $5
    return Date.new(n1, n3, n5)          if n1 > 12
    return Date.new(n5 + 2000, n1, n3)     if  n5 < 50
    return Date.new(n5 + 1900, n1, n3)    if  n5 < 100
    return Date.new(n5, n1, n3)
  end

  # Date.today.to_s
  today = DateTime::now()
      
  if $3
    dt = Date.new(today.year, n1, n3)
    if (dt < today) and not backwards
      dt += 365
    elsif (dt > today) and backwards
      dt -= 365
    end
    return dt.to_s
  end

  dt = Date.new(today.year, today.month, today.day)
  if not backwards
    while dt.day != n1
      dt += 1
    end
  elsif backwards
    while dt.day != n1
      dt -= 1
    end
  end
  dt
end

#=============================================================================

def make_select (name, onchange, selected, *l)
  s = "<SELECT name='#{name}' #{onchange ? ("onchange='#{onchange}'") : ""}>\n"
  l.each do |choice|
    s += "\t<OPTION #{(choice == selected) ? 'SELECTED' : ''} VALUE='#{choice}'>#{choice}</OPTION>\n"
  end
  s += "</selECT>\n"
end

#=============================================================================
  
def db_db(db)
  $dbh = DBI.connect("DBI:Mysql:#{db}:localhost", "keleher", "herbyd")
end


def db_do(q, *args)
  $dbh.do(q, *args)
end


def db_firsts(q, *args)
  rows = db_rows(q, *args)
  return nil unless rows
  rows.map {|row| row[0]}
end


def db_scalar(q, *args)
  row = db_row(q, *args)
  row ? row[0] : row
end


def db_row(q, *args)
  row = $dbh.select_one(q, *args)
  return nil unless row
  row.map {|x| x.to_s}
end


def db_rows(q, *args)
  rows = $dbh.select_all(q, *args)
  return nil unless (rows.length > 0)
  rows.map do |row|
    row.map {|x| x.to_s}
  end
end


def db_row_map(q, *args)
  sth = $dbh.execute(q, *args)
  h = sth.fetch_hash
  sth.finish
  h
end


def db_rows_map(q, *args)
  sth = $dbh.execute(q, *args)
  rows = []
  while row = sth.fetch_hash do
    rows.push(row)
  end
  sth.finish
  rows
end



#=============================================================================
  

# Assumes TTh class, starting on Tuesday
def schedule(from, to, fname)
  datef = parseDateObj(from)
  datet = parseDateObj(to)
  raise("Schedule must start from a tuesday\n")  unless datef and datet and (datef.wday == 2)

  dates = []
  weeks = []
  dhash = {}
  plus = []
  fluid = []

  while datef <= datet
    dates.push(datef.to_s)
    if datef.wday == 2
      weeks.push(datef.to_s)
      datef += 2
    else
      datef += 5
    end
  end

#  IO.foreach("topics") do |l|

  bytes = IO.read(fname)
  bytes.gsub!(/\r/, '')
  chunks = bytes.split(/\n{2,}/)
  
  chunks.each do |c|
    next unless c =~ /\w/
    if c =~ /^\+/
      plus.push(c)
    else
      if dt = parseDate(c)
        c.strip!
        c.sub!(/[^\n]*\n/, '')
        c.gsub!(/"([^"]*)";"([^"]*)"/, '<a href="\1"><b>\2</b></a>')
        dhash[dt] = c
      else
        fluid.push(c)
      end
    end
  end

#  puts " dates #{dates.size}, fluid #{fluid.size}"

  dates.each do |d|
    if not dhash[d]
      if dhash[d] = fluid.shift
        dhash[d].gsub!(/"([^"]*)";"([^"]*)"/, '<a href="\1"><b>\2</b></a>')
      end
    end
  end

  plus.each do |c|
    c.sub!(/./,'')		# trim the leading '+'
    dt = parseDate(c)
    c.sub!(/[^\n]*\n/, '')
    c.gsub!(/"([^"]*)";"([^"]*)"/, '<a href="\1"><b>\2</b></a>')
    dhash[dt] = '<font color=blue>' + c + '</font>' + (dhash[dt] ? "<br>" + dhash[dt] : '')
  end

  print <<-EOM
    <p>
	<center>
	<table cellpadding=4 class=calendar border=1>
	<tr><th colspan=2 class=day>Tuesday</th><th colspan=2 class=day>Thursday</th> 
  EOM

  weeks.each do |w|
    tuesObj = parseDateObj(w)
    thursObj = tuesObj + 2

    puts "<tr>"
    [tuesObj,thursObj].each do |dtObj|
      if c = dhash[dtObj.to_s]
        c.sub!(/^(\w+:)/, '')
      end
      print "<th class=date>#{dtObj.strftime("%b %e")}</th><td class=#{$1 ? $1.sub(/:/,'') : 'lecture'}>#{c}</td>"
    end
  end

  print "</table>\n"
end
    

def tablePretty4(caption, extra, names, rows, func = nil, noheader = nil)
  altrows = ['scope=row class=spec', 'scope=row class=specalt']
  alttds = ['', 'class=alt']
  colors = ['#eeeeee', 'white']
  puts "<center><table class=pretty4 cellspacing=0 #{extra}>#{caption ? "<caption>#{caption}</caption>":""}"
  if names
    puts "<tr><th scope=col class=nobg>#{names.shift}</th>"
    names.each do |c|  
      puts "<th scope=col>#{func ? "<a href='' onclick='return #{func}(\"#{c}\")'><font size=-2>#{c}</font></a>" : c}</th>"
    end
  end

  rows.each_with_index do |row,i|
    puts "<tr>"
    puts "<th #{altrows[i % 2]}>#{row.shift}</th>" unless noheader
    
    row.each do |x| 
      if x =~ /^r(\d+):(.*)/m
        puts "<td colspan=#{$1} #{alttds[(i % 2)]}>#{($2.to_s.size > 0) ? $2 : '&nbsp;'}</td>"
      else
        puts "<td #{alttds[(i % 2)]}>#{(x.to_s.size > 0) ? x : '&nbsp;'}</td>"
      end
    end
  end
  puts "</table></center>"
end


def tableGrayWhite(caption, extra, cols, rows)
  puts "<table #{extra} cellpadding=5 cellspacing=0 border=1 rules=rows frame=box>"

  altrows = ['scope=row class=spec', 'scope=row class=specalt']
  alttds = ['', 'class=alt']

  if cols
    puts "<tr>"
    cols.each {|fld| puts "<th>#{fld}</th>"}
  end
  
  colors = ['#eeeeee', 'white']

  rows.each_with_index do |row, i|
    puts "<tr bgcolor='#{colors[i%2]}'>"
    row.each do |x|
      if x =~ /^r(\d+):(.*)/m
        puts "<td #{alttds[(i % 2)]} colspan=#{$1}>#{$2}</td>"
      else
        puts "<td #{alttds[(i % 2)]}>#{x}</td>"
      end
    end
  end
  puts '</table>'
end


def tablePapaya(caption, extra, cols, rows)
  altrows = ['scope=row class=spec', 'scope=row class=specalt']
  alttds = ['', 'class=alt']

  puts "<table #{extra} cellpadding=5 cellspacing=0 border=1 rules=rows frame=box>"
  if cols
    puts "<tr bgcolor=papayawhip>"
    cols.each {|fld| puts "<th>#{fld}</th>"}
  end
  
  colors = ['#eeeeee', 'white']

  rows.each_with_index do |row, i|
    puts "BLAH #{row.size} BLAH"
    puts "<tr bgcolor='#{colors[i%2]}'>"
    row.each do |x|
      if x =~ /^r(\d+):(.*)/m
        puts "<td colspan=#{$1}>#{$2}</td>"
      else
        puts "<td>#{(x.to_s.size > 0) ? x : '&nbsp;'}</td>"
      end
    end
  end
  puts '</table>'
end


