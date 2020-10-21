require 'spec_helper'

describe 'mesos::config', :type => :class do

  let(:owner) { 'mesos' }
  let(:group) { 'mesos' }

  let(:params){{
    :conf_dir => '/etc/mesos',
    :log_dir  => '/var/log/mesos',
    :owner    => owner,
    :group    => group,
  }}

  it { should contain_file('/etc/default/mesos').with({
    'ensure'  => 'present',
    'owner'   => owner,
    'group'   => group,
    'mode'    => '0644',
    'require' => 'Package[mesos]',
  }) }

  it 'has default log dir' do
    should contain_file(
      '/etc/default/mesos'
    ).with_content(/LOGS="\/var\/log\/mesos"/)
  end

  it 'has default ulimit' do
    should contain_file(
      '/etc/default/mesos'
    ).with_content(/ULIMIT="-n 8192"/)
  end

  context 'setting ulimit' do
    let(:params){{
      :ulimit => 16384,
    }}

    it { should contain_file(
      '/etc/default/mesos'
      ).with_content(/ULIMIT="-n 16384"/)
    }
  end

  context 'setting log dir' do
    let(:params){{
      :log_dir => '/srv/mesos/log',
    }}
    it { should contain_file(
      '/etc/default/mesos'
      ).with_content(/LOGS="\/srv\/mesos\/log"/)
    }
  end

  context 'with zookeeper' do
    let(:params){{
      :zookeeper => 'zk://192.168.1.100:2181/mesos',
    }}
    it { should contain_file(
      '/etc/mesos/zk'
      ).with(
      :ensure => 'present'
      ).with_content(/^zk:\/\/192.168.1.100:2181\/mesos/)
    }
  end

  context 'with manage_zk_file false' do
    let(:params){{
      :manage_zk_file => false,
      :zookeeper      => 'zk://192.168.1.100:2181/mesos',
    }}
    it { should_not contain_file(
      '/etc/mesos/zk'
      )
    }
  end

  context 'setting environment variables' do
    let(:params){{
      :env_var => {
        'JAVA_HOME' => '/usr/bin/java',
        'MESOS_HOME' => '/var/lib/mesos',
      },
    }}

    it { should contain_file(
      '/etc/default/mesos'
    ).with_content(/export JAVA_HOME="\/usr\/bin\/java"/) }

    it { should contain_file(
      '/etc/default/mesos'
    ).with_content(/export MESOS_HOME="\/var\/lib\/mesos"/) }
  end

  context 'set LOGS variable' do
    let(:file) { '/etc/default/mesos' }
    let(:params) {{
      :log_dir => '/var/log/mesos'
    }}

    it { should contain_file(file).with_content(/LOGS="\/var\/log\/mesos"/) }
  end
end
