module Rack
  module OAuth2
    class Server
      
      # Access token. This is what clients use to access resources.
      #
      # An access token is a unique code, associated with a client, an identity
      # and scope. It may be revoked, or expire after a certain period.
      class AccessToken < Sequel::Model(:access_tokens)
        unrestrict_primary_key
        class << self

          # Creates a new AccessToken for the given client and scope.
          def create_token_for(client, scope)
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            token = { :id=>Server.secure_random, 
                      :scope=>scope, 
                      :client_id=>client.id,
                      :created_at=>Time.now, 
                      :expires_at=>nil, 
                      :revoked=>nil 
                    }
            
            client.token_granted
            
            super( token )
            
          end

          # Find AccessToken from token. Does not return revoked tokens.
          def from_token(token)
            self[token]
          end

          # Get an access token (create new one if necessary).
          def get_token_for(identity, client, scope)
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            scope_string = scope.to_json.gsub('\"', '"').gsub('","', '", "') #hack
            unless token = self[:identity => identity, :scope => scope_string, :client_id => client.id, :revoked => nil]
              values = { :id => Server.secure_random, 
                        :identity => identity, 
                        :scope => scope,
                        :client_id => client.id,
                        :created_at => Time.now,
                        :expires_at => nil, 
                        :revoked => nil }
             
              token = self.create( values )
              client.token_granted
            end
            token
          end

          # Find all AccessTokens for an identity.
          def from_identity(identity)
            self.filter( :identity=>identity )
          end

          # Returns all access tokens for a given client, Use limit and offset
          # to return a subset of tokens, sorted by creation date.
          def for_client(client_id, offset = 0, limit = 100)
            self.filter( :client_id=>client_id ).order(:created_at.asc).limit(limit, offset)
          end

          # Returns count of access tokens.
          #
          # @param [Hash] filter Count only a subset of access tokens
          # @option filter [Integer] days Only count that many days (since now)
          # @option filter [Boolean] revoked Only count revoked (true) or non-revoked (false) tokens; count all tokens if nil
          # @option filter [String, ObjectId] client_id Only tokens grant to this client
          def count(filter = {})
            select = {}
            if filter[:days]
              if filter[:revoked]
                select[:revoked] = (Date.today - filter[:days])..(Date.today)
              else
                select[:created_at] = (Date.today - filter[:days])..(Date.today)
              end
            elsif filter.has_key?(:revoked)
              select[:revoked] = filter[:revoked] ? { :$ne=>nil } : { :$eq=>nil }
            end
            select[:client_id] = filter[:client_id] if filter[:client_id]
            self.find(select)
            
          end

          def historical(filter = {})
            days = filter[:days] || 60
            
            #TODO: finish this as it is needed for the admin interface!
            #colletion.run("select count(*) from clients group by date_trunc('day', created_at);")
        
=begin            
            select = { :$gt=> { :created_at=>Time.now - 86400 * days } }
            select = {}
            if filter[:client_id]
              select[:client_id] = BSON::ObjectId(filter[:client_id].to_s)
            end
            raw = Server::AccessToken.collection.group("function (token) { return { ts: Math.floor(token.created_at / 86400) } }",
              select, { :granted=>0 }, "function (token, state) { state.granted++ }")
            raw.sort { |a, b| a["ts"] - b["ts"] }
=end            
            
          end

          def collection
            Server.database
          end
          
        end
        
        alias :token :id
        
        def scope
          JSON.parse( self[:scope] )
        end

        # Updates the last access timestamp.
        def access!
          
          if self[:last_access].nil? || last_access < Time.now
            self[:prev_access] = self[:last_access] 
            self[:last_access] = Time.now
            save
          end
        end

        # Revokes this access token.
        def revoke!
          self[:revoked] = Time.now
          save
          Client[client_id].token_revoked
        end
        
      end

    end
  end
end
