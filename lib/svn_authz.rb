class SvnAuthz
  # Constructor - a nil path is defined for unit testing
  #

  def initialize(authz_file)
    load(authz_file.nil? ? authz_file : File.open(authz_file, 'r'))
  end

  # Determine if a rule applies to a user
  #
  def user_included?(user,selector)
    if  selector == user || selector=='*'
      true
    elsif user.nil?
      selector=='$anonymous'
    elsif selector=='$authenticated'
      true
    elsif selector =~ /^~(.+)$/
      !user_included?(user,$1)
    else
      group_members(selector).include? user
    end
  end

  # Determine users in group,
  # flattening groups ins groups, and resolves all aliases
  def group_members(selector,cycle={})
    return [selector]  if !(selector =~ /^([&@])(.*)$/)
    selector_name = $2
    case $1
    when '&'
      name = @aliases[selector_name]
      fail "Undefined #{selector}" if !name
      return [name]
    when '@'
      if !@group_members_cache[selector_name]
        fail "Cycle in definition of #{selector}" if cycle[selector_name]
        fail "Undefined  #{selector}" if !@groups[selector_name]
        cycle[selector_name] = true
        members = []
        @groups[selector_name].split(/,/).each do |member|
          members |= group_members(member.strip,cycle)
        end
        @group_members_cache[selector_name] = members
      end
      @group_members_cache[selector_name]
    end
  end

  # Load configuration source
  #
  def load(source)
    @aliases = {}

    @group_members_cache = {}
    if source.nil?
      sections = {'aliases' => {},'groups' => {}};
    else
      sections = parse(source)
    end
    if s = sections.delete('aliases')
      @aliases = s
    else @aliases = {}
    end
    if s = sections.delete('groups')
      @groups = s
    else @groups = {}
    end
    @paths = sections
    # only paths remain - sort them from most specific to least specific
    # N.B. any path w/o a repository follows like path with a repository
    # i.e. 'ra:/d1', 'rb:/d1', '/d1',  'ra:/', 'rb:/', '/'
    #
    @path_routes = sections.keys.sort do |a,b|
      (a_repo,a_path) = (['']+a.split(':'))[-2,2]
      (b_repo,b_path) = (['']+b.split(':'))[-2,2]
      b_path==a_path ? b_repo <=> a_repo : b_path <=> a_path
    end
  end

  # Parse the input file 
  #
  def parse(io)
    section = nil
    sections = {}
    io.each {|line|
      cmd,comment = line.strip.split(/#/, 2)
      if cmd.nil?
        cmd = ''
      else
        cmd = cmd.strip
      end
      next if cmd.length == 0
      if cmd =~ /^\[(.*)\]$/
        sections[section = $1] = {}
      else
        fail "Syntax error '#{cmd}'" if section.nil?
        kv = cmd.split(/=/, 2)
        fail "Syntax error '#{cmd}'" if kv.length!=2
        key = kv[0].strip
        fail "Syntax error '#{cmd}'" if key.length==0
        sections[section][key] = kv[1].strip
      end
    }
    sections
  end

  # Determine user permissions for a path
  #
  # Determine user permissions for a path
  #
  def permissions(username,path)
    # walk the path from the most specific to the least specific scanning the
    # rules at each way point, capturing any explicit user name match and merging
    # any matching group permissios. The first such match is the result
    #
    repo , dir = path.split(':')
    @path_routes.each do |point|
      next if !(path =~ /^#{point}/) && !(dir =~ /^#{point}/)
      gperms = []
      uperms = nil
      @paths[point].each do |selector,rule|
        fail "Syntax error #{selector}='#{rule}'" if rule.tr('^rw','')!=rule
        p = (rule=='rw')? ['r', 'w'] : [rule]
        if username==selector || @aliases[username]==selector
          uperms = p                      # user permssion
        elsif user_included?(username,selector)
          gperms |= p                     # group permission
        end
      end
      gperms |= [uperms] if !uperms.nil?  # user perms extend group perms
      return gperms.sort.join('') if !gperms.empty?
    end
    ''    # no matching rule
  end


end