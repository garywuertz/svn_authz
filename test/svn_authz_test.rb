$:.unshift File.join(File.dirname(__FILE__),'..','lib')

require 'test/unit'
require 'svn_authz'
require 'stringio'

class SvnAuthzTest < Test::Unit::TestCase
  # Unit under test
  #
  def setup
    @svnauthz = SvnAuthz.new(nil)
  end
  def teardown

  end

  # Test basic parser operation
  #
  def test_parser
    errors = [
      "a=b\n[section]\c=d",
      "[section]\nc",
      "[section]\n=d"
    ]
    errors.each {|error|
      io = StringIO.new(error)
      exception = assert_raise(RuntimeError){  @svnauthz.parse(io) }
      assert_match /Syntax error/, exception.message
    }
  end

  # Test name resolution
  #
  def test_user_names
    source = <<EOF
[aliases]
admin=administrator
[groups]
g1=&admin,user1
g2=user2,user3
g3=@g1,user4
g5=g5
g6=@g4
g7=&missing
EOF
    @svnauthz.load(StringIO.new(source))
    assert_equal(['administrator'], @svnauthz.group_members('&admin'))
    assert_equal(['administrator','user1'], @svnauthz.group_members('@g1'))
    assert_equal(['user2','user3'], @svnauthz.group_members('@g2'))
    assert_equal(['administrator','user1','user4'], @svnauthz.group_members('@g3'))
    assert_equal(['g5'], @svnauthz.group_members('@g5'))
    exception = assert_raise(RuntimeError){  @svnauthz.group_members('@g6') }
    assert_match /Undefined/, exception.message
    exception = assert_raise(RuntimeError){  @svnauthz.group_members('@g7') }
    assert_match /Undefined/, exception.message

    source = <<EOF
[groups]
g6=@g7
g7=@g6
EOF
    @svnauthz.load(StringIO.new(source))
    exception = assert_raise(RuntimeError){  @svnauthz.group_members('@g7') }
    assert_match /Cycle/, exception.message
  end


  # test rule application conventions version 1.6
  #
  def test_user_included
    source = <<EOF
[aliases]
admin=administrator
[groups]
g1=user1,&admin
EOF
    io = StringIO.new(source)
    @svnauthz.load(io)
    assert_equal(true,@svnauthz.user_included?('user0','user0'))
    assert_equal(true,@svnauthz.user_included?('userxxx','*'))
    assert_equal(true,@svnauthz.user_included?(nil,'$anonymous'))
    assert_equal(true,@svnauthz.user_included?('userxx','$authenticated'))
    assert_equal(true,@svnauthz.user_included?('administrator','&admin'))
    assert_equal(true,@svnauthz.user_included?('user1','@g1'))
    assert_equal(true,@svnauthz.user_included?('administrator','@g1'))
    assert_equal(true,@svnauthz.user_included?('user1','~user2'))
    assert_equal(false,@svnauthz.user_included?('user1','user2'))
    assert_equal(false,@svnauthz.user_included?('user0','~user0'))
    assert_equal(false,@svnauthz.user_included?('userxxx','~*'))
    assert_equal(false,@svnauthz.user_included?(nil,'~$anonymous'))
    assert_equal(false,@svnauthz.user_included?('userxx','~$authenticated'))
    assert_equal(false,@svnauthz.user_included?('administrator','~&admin'))
    assert_equal(false,@svnauthz.user_included?('user1','~@g1'))
    assert_equal(false,@svnauthz.user_included?('administrator','~@g1'))
  end

  # test permissions edge cases
  #
  def test_permissios
    source = <<EOF
    [groups]
    g1=user1
    g2=user1,user2
    [/]
    * = r
    [repo1:/dir1]
    @g1 = rw
    @g2 =
    [repo1:/dir1/dir2]
    user1=
    user2=r
    [repo2:/home]
    user1 = garbage
    [/dir1]
    user2 = rw
EOF
    io = StringIO.new(source)
    @svnauthz.load(io)
    assert_equal("r",@svnauthz.permissions('user0','repo1:/'))
    assert_equal("rw",@svnauthz.permissions('user1','repo1:/dir1'))
    assert_equal("",@svnauthz.permissions('user2','repo1:/dir1'))
    assert_equal("rw",@svnauthz.permissions('user2','repo2:/dir1'))
    assert_equal("",@svnauthz.permissions('user1','repo1:/dir1/dir2'))
    assert_equal("r",@svnauthz.permissions('user2','repo1:/dir1/dir2'))
    exception = assert_raise(RuntimeError){  @svnauthz.permissions('user1','repo2:/home') }
    assert_match /Syntax error/, exception.message
  end


  def test_edge_case1
    source = <<EOF
    [/dir1]
    * = r
    [repo1:/dir1]
    * =
    [-repo2:/dir1]
    * =
EOF
    io = StringIO.new(source)
    @svnauthz.load(io)
    assert_equal "r", @svnauthz.permissions('anybody','other_repo:/dir1')
    assert_equal "", @svnauthz.permissions('anybody','repo1:/dir1') 
    assert_equal "",@svnauthz.permissions('anybody','-repo2:/dir1')
  end


  # Putting it all to together - examples from the subversion book
  #
  def test_book
    source = <<EOF
[aliases]
harry=Harry
hewlett=Hugh
joe=Joe
packard=Packard
sally=Sally
[groups]
calc-developers = &harry, &sally, &joe
calc-owners = &hewlett, &packard
calc = @calc-developers, @calc-owners
[calc:/branches/calc/bug-142]
harry = rw
sally = r
# give sally write access only to the 'testing' subdir
[calc:/branches/calc/bug-142/testing]
sally = rw
# deny harry
[calc:/branches/calc/bug-142/secret]
harry =
[calendar:/projects/calendar]
$anonymous = r
$authenticated = rw
# Any calc participant has read-write access...
[calc:/projects/calc]
@calc = rw
# ...but only allow the owners to make and modify release tags.
[calc:/projects/calc/tags]
~@calc-owners = r
EOF
    io = StringIO.new(source)
    @svnauthz.load(io)

    assert_equal("rw",@svnauthz.permissions('harry','calc:/branches/calc/bug-142'))
    assert_equal("r",@svnauthz.permissions('sally','calc:/branches/calc/bug-142'))
    assert_equal("rw",@svnauthz.permissions('harry','calc:/branches/calc/bug-142/testing'))
    assert_equal("rw",@svnauthz.permissions('sally','calc:/branches/calc/bug-142/testing'))
    assert_equal("",@svnauthz.permissions('harry','calc:/branches/calc/bug-142/secret'))

    assert_equal("rw",@svnauthz.permissions('anybody','calendar:/projects/calendar'))
    assert_equal("r",@svnauthz.permissions(nil,'calendar:/projects/calendar'))
    devels = ['Harry', 'Sally', 'Joe']
    owners = ['Hugh', 'Packard']
    (devels+owners).each {|u| assert_equal("rw",@svnauthz.permissions(u,'calc:/projects/calc'),"#{u}")}
    devels.each {|u| assert_equal("r",@svnauthz.permissions(u,'calc:/projects/calc/tags'),"#{u}")}
    owners.each {|u| assert_equal("rw",@svnauthz.permissions(u,'calc:/projects/calc/tags'),"#{u}")}
  end
end