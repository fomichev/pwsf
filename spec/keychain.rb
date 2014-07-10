if File.exists?(File.join(File.expand_path('../..', __FILE__), '.git'))
  $:.unshift(File.expand_path('../../lib', __FILE__))
end

require 'rspec'
require 'passwordsafe'

test_db = [
  {
    uuid: "g\xE0^%\xA3<B5\xB5q\x9C\xEC\x9B\xD5\xE6A".force_encoding('ASCII-8BIT'),
    title: "Test eight",
    username: "user8",
    password: "my password",
    notes: "shift double click action set = run command",
    create_time: 1339168618,
    last_modify_time_time: 1339168764,
    pwd_history: "1ff00",
    sdclick_action: 8,
  },
  {
    uuid: "\xE8t\x98\x800\x94K\xA6\xBA\xD2\xA0;uiz\xC2".force_encoding('ASCII-8BIT'),
    title: "Test Four",
    username: "user4",
    password: "pass4",
    create_time: 1311392620,
    access_time: 1311400802,
    expiry_time: 1327636140,
    last_modify_time_time: 1311907753,
    pwd_policy: "f00000e001001001001",
    pwd_history: "1ff00",
  },
  {
    uuid: "{\xED\xC6\x8B@\xA5CH\xBC+3\xDCPw+\xB3".force_encoding('ASCII-8BIT'),
    group: "Test",
    title: "Test One",
    username: "user2",
    password: "password2",
    autotype: "fdas",
    create_time: 1311386977,
    access_time: 1311400799,
    expiry_time: 1311994130,
    last_modify_time_time: 1311907737,
    pwd_history: "1ff00",
    run_command: "asdf",
  },
  {
    uuid: "0\xEEM\xACp\xC3A\x96\xB7\x9A\xA4\xBD\x95P\x85\xAC".force_encoding('ASCII-8BIT'),
    title: "Test seven",
    username: "user7",
    password: "my password",
    notes: "Symbols set for password generation",
    create_time: 1339168618,
    last_modify_time_time: 1339168719,
    pwd_policy: "f00000c001001001001",
    pwd_history: "1ff00",
    pwd_symbols: "+_-\#$%",
  },
  {
    uuid: "\xE4K\x9F\xB9\xEBCI\xB7\xB2\xE1\x05\x850\xC1\xB9C".force_encoding('ASCII-8BIT'),
    title: "Test Two",
    username: "user3",
    password: "pass3",
    create_time: 1311386990,
    access_time: 1311400798,
    last_modify_time_time: 1311907761,
    pwd_policy: "080000c001001001001",
    pwd_history: "1ff00",
  },
  {
    uuid: "\x15G\xFC\xD2\x0E\x8C@\xDF\xAAL\x10*y\xE1&\e".force_encoding('ASCII-8BIT'),
    group: "Test",
    title: "Test Nine",
    username: "user9",
    password: "DoubleClickActionTest",
    create_time: 1339362429,
    pwd_history: "1ff00",
    dclick_action: 7,
  },
  {
    uuid: "S\xBE8\xD5\x83\x05F\x88\x9D\xE5\xD6wJ\xEA".force_encoding('ASCII-8BIT'),
    title: "Test six",
    username: "user6",
    password: "my password",
    notes: "protected entry",
    create_time: 1339168618,
    last_modify_time_time: 1339168666,
    pwd_history: "1ff00",
    protected: "1",
  },
  {
    uuid: "n\xF5\xC1\xF3,\xA5N\x05\xA0\x93 \xC8\x98\x97<\x15".force_encoding('ASCII-8BIT'),
    group: "Test",
    title: "Test One",
    username: "user1",
    password: "password1",
    create_time: 1311386913,
    access_time: 1311400800,
    last_modify_time_time: 1311907724,
    pwd_policy: "b20000b001001001001",
    pwd_history: "1ff00",
  },
  {
    uuid: "\xB8\r^\xFD\xB4jO]\x88\xD2\xD5\x8A\xAD\"\x0E\x17".force_encoding('ASCII-8BIT'),
    title: "Test Five",
    username: "user5",
    password: "my password",
    notes: "email address test",
    create_time: 1339168618,
    pwd_history: "1ff00",
    email: "email@bogus.com",
  }
]

describe PasswordSafe::KeychainV3 do
  it 'should throw an error when database path is wrong' do
    expect { PasswordSafe::KeychainV3.new('/invalid/path') }.to raise_error
  end

  it 'should not throw an error when database path is correct' do
    PasswordSafe::KeychainV3.new('./simple.psafe3')
  end

  it 'should throw an error when password is wrong' do
    p = PasswordSafe::KeychainV3.new('./simple.psafe3')
    expect { p.unlock('invalid') }.to raise_error
  end

  it 'should not throw an error when password is correct' do
    p = PasswordSafe::KeychainV3.new('./simple.psafe3')
    p.unlock('bogus12345')
  end

  it 'should have correct number of test entries' do
    p = PasswordSafe::KeychainV3.new('./simple.psafe3')
    p.unlock('bogus12345')

    i = 0
    p.each { i = i + 1 }

    i.should == test_db.size
  end

  it 'should have correct test entries' do
    p = PasswordSafe::KeychainV3.new('./simple.psafe3')
    p.unlock('bogus12345')

    p.each do |r|
      found = false
      test_db.each do |t|

        if t[:uuid] == r.get_field(:uuid)
          found = true

          r.each do |k, v|
            t[k].should == v
          end

          break
        end
      end

      found.should be_true
    end
  end
end
