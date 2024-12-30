#
# Cookbook:: iptables-ng
# Recipe:: manage
#
# Copyright:: 2013, Chris Aumann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# This was implemented as a internal-only provider.
# Apparently, calling a LWRP from a LWRP doesnt' really work with
# subscribes / notifies. Therefore, using this workaround.
require 'shellwords'

module Iptables
  module Manage
    def extract_current(ip_version, table)
      binary = ip_version == 6 ? 'ip6tables-save' : 'iptables-save'
      chains = Mash.new
      rules = []
      so = shell_out("#{binary} -t #{table}")
      unless so.exitstatus == 0
        return {:chains => chains, :rules => rules}
      end
      lines = so.stdout.split("\n")

      lines.each do |line|
        token = line[0]
        next if token == "#"
        next if token == "*"
        if token == ":"
          chain, policy, _ = line[1..].shellsplit
          chains[chain] = policy
          next
        end
        if token == "-"
          rules << line
        end
      end
      return {:chains => chains, :rules => rules}
    end
    def create_iptables_rules(ip_version)
      rules = {}

      # Retrieve all iptables rules for this ip_version,
      # as well as default policies
      Dir["/etc/iptables.d/*/*/*.rule_v#{ip_version}",
          '/etc/iptables.d/*/*/default'].each do |path|
        # /etc/iptables.d/#{table}/#{chain}/#{rule}.rule_v#{ip_version}
        table, chain, filename = path.split('/')[3..5]
        rule = ::File.basename(filename)

        # Skip nat table if ip6tables doesn't support it
        next if table == 'nat' &&
                node['iptables-ng']['ip6tables_nat_support'] == false &&
                ip_version == 6

        # Skip deactivated tables
        next unless node['iptables-ng']['enabled_tables'].include?(table)

        # Create hashes unless they already exist, and add the rule
        rules[table] ||= {}
        rules[table][chain] ||= {}
        rules[table][chain][rule] = ::File.read(path)
      end

      iptables_restore = ''
      rules.each do |table, chains|
        iptables_restore << "*#{table}\n"
        existing = extract_current(ip_version, table)

        # Get default policies and rules for this chain
        default_policies = chains.each_with_object({}) do |rule, new_chain|
          new_chain[rule[0]] = rule[1].select { |k, _| k == 'default' }
        end

        all_chain_rules = chains.each_with_object({}) do |rule, new_chain|
          new_chain[rule[0]] = rule[1].reject { |k, _| k == 'default' }
        end

        # Apply default policies first
        default_policies.each do |chain, policy|
          iptables_restore << ":#{chain} #{policy['default'].chomp}\n"
        end

        existing[:chains].each do |chain, policy|
          if default_policies[chain].nil?
            iptables_restore << ":#{chain} #{policy.chomp}\n"
          end
        end

        existing[:rules].each do |rule|
          unless rule.include?('iptables-ng::chef')
            iptables_restore << "#{rule}\n"
          end
        end
        # Apply rules for this chain, but sort before adding
        all_chain_rules.each do |_chain, chain_rules|
          chain_rules = chain_rules.sort
          a, b = chain_rules.partition { |k, _| k.start_with?('9') }
          b.each { |r| iptables_restore << "#{r.last.chomp}\n" }
          a.each { |r| iptables_restore << "#{r.last.chomp}\n" }
          #chain_rules.sort.each { |r| iptables_restore << "#{r.last.chomp}\n" }
        end

        iptables_restore << "COMMIT\n"
      end

      Chef::Resource::File.new(node['iptables-ng']["script_ipv#{ip_version}"], run_context).tap do |file|
        file.owner('root')
        file.group(node['root_group'])
        file.mode(0o600)
        file.content(iptables_restore)
        file.run_action(:create)
      end
    end
  end
end
