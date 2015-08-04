require "yaml"

#TODO: Should I feel about these 'global' helper functions?
def hashify(segments, value)
  return {} if segments.empty?
  s, *rest = segments
  if rest.empty?
    { s => value }
  else
    { s => hashify(rest, value) }
  end
end

class Hash
  # idea snatched from deep_merge in Rails source code
  def deep_safe_merge(other_hash)
    self.merge(other_hash) do |key, oldval, newval|
      oldval = oldval.to_hash if oldval.respond_to?(:to_hash)
      newval = newval.to_hash if newval.respond_to?(:to_hash)
      if oldval.is_a? Hash
        if newval.is_a? Hash
          oldval.deep_safe_merge(newval)
        else
          oldval
        end
      else
        newval
      end
    end
  end

  def deep_safe_merge!(other_hash)
    replace(deep_safe_merge(other_hash))
  end

end

class DefaultFinder
  require 'parser/current'
  require 'action_view'

  class << self

    def tree_search(root, child_method = :children, &block)
      return root if yield root

      if root.respond_to?(child_method)
        root.send(child_method).each do |c|
          ret = tree_search(c, child_method, &block)
          return ret if ret
        end

        nil
      else
        nil
      end
    end

    def tree_find_all(root, child_method = :children, &block)
      return [root] if yield root

      if root.respond_to?(child_method)
        root.send(child_method).map do |c|
          tree_find_all(c, child_method, &block).flatten
        end.flatten
      else
        []
      end
    end

    def find_method(root, methodName)
      tree_search root do |n|
        succ = n.is_a?(Parser::AST::Node) &&
          n.type == :send &&
          n.children[1] == methodName
        succ
      end
    end

    def find_methods(root, methodName)
      tree_find_all root do |n|
        succ = n.is_a?(Parser::AST::Node) &&
          n.type == :send &&
          n.children[1] == methodName
        succ
      end
    end

    def is_hash_with_key(node, key)
      n = node
      succ = n.is_a?(Parser::AST::Node) &&
        n.type == :pair &&
        n.children[0].is_a?(Parser::AST::Node) &&
        n.children[0].children[0] == key
      succ
    end

    def first_arg(node)
      raise "not a send node (#{ node })" unless node.is_a?(Parser::AST::Node) && node.type == :send
      node.children[2].children[0]
    end

    def findHashVal(root, key)
      hash_node = tree_search root do |n|
        is_hash_with_key n, key
      end

      if hash_node
        valNode = hash_node.children[1]
        if valNode.type == :dstr
          val = valNode.children[1].children[0]
        else
          val = valNode.children[0]
        end

        if val.is_a? String
          val
        else
          puts "unhandled val: #{val}"
          ''
        end
      end
    end

    def erb_tree(file)
      s = ActionView::Template::Handlers::Erubis.new File.read(file)
      src = s.src
      Parser::CurrentRuby.parse(src)
    end

    def find_translations(root)
      tnodes = find_methods(root, :t)
      if tnodes.length > 0
        tnodes.inject({}) do |h, atrans|
          key = first_arg(atrans).gsub(/^\./,'')

          dval = findHashVal(atrans, :default)
          h[key] =  dval

          h
        end
      end
    end

    def add_missing_defaults(file, current)
      return current if file.split(".").last == "haml"

      ret = current.dup
      begin
        ts = find_translations(erb_tree(file))
        ret.keys.each do |k|
          if ret[k] == '' && parsed_val = ts[k.split('.').last]
            ret[k] = parsed_val.encode(Encoding::US_ASCII)
          end
        end

        ret
      rescue Parser::SyntaxError => e
        # sometimes erb fails to parse.
        # this probably shouldn't crash the program :)
        ret
      end
    end
  end
end

class MissingT

  class FileReader
    def read(file)
      IO.readlines(file).each do |line|
        yield line
      end
    end
  end

  VERSION = "0.4.1"

  def initialize(options={})
    @reader = options.fetch(:reader, FileReader.new)
    @languages = options[:languages]
    @path = options[:path]
  end

  def run
    missing = {}
    collect_missing.each do |file, message_strings|
      message_strings = DefaultFinder.add_missing_defaults(file, message_strings)

      message_strings.each do |message_string, value|
        missing.deep_safe_merge! hashify(message_string.split('.'), value)
      end
    end

    missing.each do |language, missing_for_language|
      puts
      puts({"#{language}" => missing_for_language}.to_yaml)
    end
  end

  def collect_missing
    ts = translation_keys
    #TODO: If no translation keys were found and the languages were not given explicitly
    # issue a warning and bail out
    languages = @languages ? @languages : ts.keys
    get_missing_translations(translation_keys, translation_queries, languages)
  end

  def get_missing_translations(keys, queries, languages)
    languages.each_with_object({}) do |lang, missing|
      get_missing_translations_for_language(keys, queries, lang).each do |file, queries_for_language|
        missing[file] ||= {}
        missing[file].merge!(queries_for_language)
      end
    end
  end

  def translation_keys
    locales_pathes = ["config/locales/**/*.yml", "vendor/plugins/**/config/locales/**/*yml", "vendor/plugins/**/locale/**/*yml"]
    locales_pathes.each_with_object({}) do |path, translations|
      Dir.glob(path) do |file|
        t = open(file) { |f| YAML.load(f.read) }
        translations.deep_safe_merge!(t)
      end
    end
  end

  def translation_queries
    files_with_i18n_queries.each_with_object({}) do |file, queries|
      queries_in_file = extract_i18n_queries(file)
      if queries_in_file.any?
        queries[file] = queries_in_file
      end
    end
    #TODO: remove duplicate queries across files
  end

  def has_translation?(keys, lang, query)
    i18n_label(lang, query).split('.').each do |segment|
      return false unless segment =~ /#\{.*\}/ or (keys.respond_to?(:key?) and keys.key?(segment))
      keys = keys[segment]
    end
    true
  end

  def files_with_i18n_queries
    if @path
      path = File.expand_path(@path)
      if File.file?(path)
        [@path]
      else
        path.chomp!('/')
        [
          Dir.glob("#{path}/**/*.erb"),
          Dir.glob("#{path}/**/*.haml"),
          Dir.glob("#{path}/**/*.rb")
        ]
      end
    else
      [
        Dir.glob("app/**/*.erb"),
        Dir.glob("app/**/*.haml"),
        Dir.glob("app/**/models/**/*.rb"),
        Dir.glob("app/**/controllers/**/*.rb"),
        Dir.glob("app/**/helpers/**/*.rb")
      ]
    end.flatten
  end

  def extract_i18n_queries(file)
    relative_path = file.split(/\//)
    relative_path.shift if relative_path[0] == 'app'
    relative_path.shift if %w(helpers controllers models views mailer).include?(relative_path[0])
    relative_path.shift if %w(mailer).include?(relative_path[0])
    relative_path[-1].gsub!(/\..*$/, '')
    relative_path[-1].gsub!(/^_/, '')
    relative_path[-1].gsub!(/_(controller|helper)$/, '')
    relative_path = relative_path.join('.')
    ({}).tap do |queries|
      @reader.read(File.expand_path(file)) do |line|
        qs = scan_line(line, relative_path)
        queries.merge!(qs)
      end
    end
  end

private

  def get_missing_translations_for_language(keys, queries, l)
    queries.each_with_object({}) do |(file, queries_in_file), missing_translations|
      queries_with_no_translation = queries_in_file.reject { |q, _| has_translation?(keys, l, q) }
      if queries_with_no_translation.any?
        missing_translations[file] = add_langauge_prefix(queries_with_no_translation, l)
      end
    end
  end

  def add_langauge_prefix(qs, l)
    qs.each_with_object({}) do |(q, v), with_prefix|
      with_prefix["#{l}.#{q}"] = v
    end
  end

  def i18n_label(lang, query)
    "#{lang}.#{query}"
  end

  def scan_line(line, relative_path)
    with_parens = /[^\w]+(?:I18n\.translate|I18n\.t|translate|t)\s*\((['"](.*?)['"].*?)\)/
    no_parens = /[^\w]+(?:I18n\.translate|I18n\.t|translate|t)\s+(['"](.*?)['"].*?)/
    [with_parens, no_parens].each_with_object({}) do |pattern, extracted_queries|
      line.scan(pattern).each do |m|
        if m.any?
          message_string = m[1]
          if message_string.match(/^\./)
            message_string = relative_path + message_string
          end
          _, *options = m[0].split(',')
          extracted_queries[message_string] = extract_default_value(options)
        end
      end
    end
  end

  def extract_default_value(message_string_options)
    [/:default\s*=>\s*['"](.*)['"]/, /default:\s*['"](.*)['"]/].each do |default_extractor|
      message_string_options.each do |option|
        if default_key_match=default_extractor.match(option)
          return default_key_match[1]
        end
      end
    end
    ''
  end


end
