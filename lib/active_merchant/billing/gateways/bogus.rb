module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    # Bogus Gateway
    class BogusGateway < Gateway
      AUTHORIZATION = '1'
      AUTHORIZATION_CAPTURE_FAILED_REFERENCE = '3'

      SUCCESS_MESSAGE = "Bogus Gateway: Forced success"
      FAILURE_MESSAGE = "Bogus Gateway: Forced failure"
      ERROR_MESSAGE = "Bogus Gateway: Use CreditCard number 1 for success, 2 for exception and anything else for error"
      CREDIT_ERROR_MESSAGE = "Bogus Gateway: Use CreditCard number 1 for success, 2 for exception and anything else for error"
      UNSTORE_ERROR_MESSAGE = "Bogus Gateway: Use trans_id 1 for success, 2 for exception and anything else for error"
      CAPTURE_ERROR_MESSAGE = "Bogus Gateway: Use authorization number 1 for exception, 2 for error and anything else for success"
      VOID_ERROR_MESSAGE = "Bogus Gateway: Use authorization number 1 for exception, 2 for error and anything else for success"
      REFUND_ERROR_MESSAGE = "Bogus Gateway: Use trans_id number 1 for exception, 2 for error and anything else for success"

      self.supported_countries = ['US']
      self.supported_cardtypes = [:bogus]
      self.homepage_url = 'http://example.com'
      self.display_name = 'Bogus'


      def authorize(money, credit_card_or_reference, options = {})
        money = amount(money)
        case normalize(credit_card_or_reference)
        when '1'
          Response.new(true, SUCCESS_MESSAGE, {:authorized_amount => money}, :test => true, :authorization => AUTHORIZATION )
        when '3'
          Response.new(true, SUCCESS_MESSAGE, {:authorized_amount => money}, :test => true, :authorization => AUTHORIZATION_CAPTURE_FAILED_REFERENCE )
        when '2'
          Response.new(false, FAILURE_MESSAGE, {:authorized_amount => money, :error => FAILURE_MESSAGE }, :test => true)
        else
          raise Error, ERROR_MESSAGE
        end
      end

      def purchase(money, credit_card_or_reference, options = {})
        money = amount(money)
        case normalize(credit_card_or_reference)
        when '1', AUTHORIZATION
          Response.new(true, SUCCESS_MESSAGE, {:paid_amount => money}, :test => true)
        when '2'
          Response.new(false, FAILURE_MESSAGE, {:paid_amount => money, :error => FAILURE_MESSAGE },:test => true)
        else
          raise Error, ERROR_MESSAGE
        end
      end

      def create_recurring_profile(options = {})

        case normalize( options[:credit_card])
        when '1'
          Response.new(true, SUCCESS_MESSAGE, {:ProfileID => "pid1"}, :test => true)
        when '2'
          Response.new(false, FAILURE_MESSAGE, {:error => FAILURE_MESSAGE },:test => true)
        else
          raise Error, ERROR_MESSAGE
        end
      end

      def update_profile(profile_id, options = {})
        case profile_id
        when "pid1"
          Response.new(true, SUCCESS_MESSAGE, {:ProfileID => "pid1"}, :test => true)
        else
          raise Error, ERROR_MESSAGE
        end
      end

      def suspend_profile(profile_id, options = {})
        case profile_id
        when "pid1"
          Response.new(true, SUCCESS_MESSAGE, {:ProfileID => "pid1"}, :test => true)
        else
          raise Error, ERROR_MESSAGE
        end
      end

      def remove_profile(profile_id, options = {})
        case profile_id
        when '1'
          Response.new(true, SUCCESS_MESSAGE, :test => true)
        when '2'
          Response.new(false, FAILURE_MESSAGE, {:error => FAILURE_MESSAGE }, :test => true)
        else
          raise Error, ERROR_MESSAGE
        end
      end


      def bill_outstanding_amount(profile_id, options = {})
        case profile_id
        when "pid1"
          Response.new(true, SUCCESS_MESSAGE, {:ProfileID => "pid1"}, :test => true)
        else
          raise Error, ERROR_MESSAGE
        end
      end


      def credit(money, credit_card_or_reference, options = {})
        if credit_card_or_reference.is_a?(String)
          deprecated CREDIT_DEPRECATION_MESSAGE
          return refund(money, credit_card_or_reference, options)
        end

        money = amount(money)
        case normalize(credit_card_or_reference)
        when '1'
          Response.new(true, SUCCESS_MESSAGE, {:paid_amount => money}, :test => true )
        when '2'
          Response.new(false, FAILURE_MESSAGE, {:paid_amount => money, :error => FAILURE_MESSAGE }, :test => true)
        else
          raise Error, CREDIT_ERROR_MESSAGE
        end
      end

      def refund(money, reference, options = {})
        money = amount(money)
        case reference
        when '1'
          raise Error, REFUND_ERROR_MESSAGE
        when '2'
          Response.new(false, FAILURE_MESSAGE, {:paid_amount => money, :error => FAILURE_MESSAGE }, :test => true)
        else
          Response.new(true, SUCCESS_MESSAGE, {:paid_amount => money}, :test => true)
        end
      end

      def capture(money, reference, options = {})
        money = amount(money)
        case reference
        when '1'
          Response.new(true, SUCCESS_MESSAGE, {:paid_amount => money}, :test => true)
        when '2'
          Response.new(false, FAILURE_MESSAGE, {:paid_amount => money, :error => FAILURE_MESSAGE }, :test => true)
        when '3'
            Response.new(false, FAILURE_MESSAGE, {:paid_amount => money, :error => FAILURE_MESSAGE }, :test => true)
        else
          raise Error, CAPTURE_ERROR_MESSAGE
        end
      end

      def void(reference, options = {})
        case reference
        when '1'
          raise Error, VOID_ERROR_MESSAGE
        when '2'
          Response.new(false, FAILURE_MESSAGE, {:authorization => reference, :error => FAILURE_MESSAGE }, :test => true)
        else
          Response.new(true, SUCCESS_MESSAGE, {:authorization => reference}, :test => true)
        end
      end

      def store(credit_card_or_reference, options = {})
        case normalize(credit_card_or_reference)
        when '1'
          Response.new(true, SUCCESS_MESSAGE, {:billingid => '1'}, :test => true, :authorization => AUTHORIZATION)
        when '2'
          Response.new(false, FAILURE_MESSAGE, {:billingid => nil, :error => FAILURE_MESSAGE }, :test => true)
        else
          raise Error, ERROR_MESSAGE
        end
      end

      def remove_credit_card(reference, options = {})
        case reference
        when '1'
          Response.new(true, SUCCESS_MESSAGE, :test => true)
        when '2'
          Response.new(false, FAILURE_MESSAGE, {:billingid => nil, :error => FAILURE_MESSAGE }, :test => true)
        else
          raise Error, ERROR_MESSAGE
        end
      end

      def unstore(reference, options = {})
        case reference
        when '1'
          Response.new(true, SUCCESS_MESSAGE, {}, :test => true)
        when '2'
          Response.new(false, FAILURE_MESSAGE, {:error => FAILURE_MESSAGE },:test => true)
        else
          raise Error, UNSTORE_ERROR_MESSAGE
        end
      end

      def get_profile_details(profile_id)
        Response.new(true, SUCCESS_MESSAGE,
          {"RecurringPaymentsSummary" => {
            "NextBillingDate"       => Date.today + 30
          }}, :test =>true )
      end

      def credit_card_detail(reference)

        Response.new(true, SUCCESS_MESSAGE,
          {:credit_card => {
            "type"       => "visa",
            "first_name" => "test_first_name",
            "last_name"  => "test_last_name",
            "number"     => "************1234",
            "month"       => "02",
            "year"      => "2017",
            "billing_address" => {
              "address1" => "test_address1",
              "city" => "test_city",
              "state" => "test_state",
              "country" => "test_country",
              "zip_code" => "zip_code"
            }
          }}, :test =>true )
      end

      private

      def normalize(credit_card_or_reference)
        if credit_card_or_reference.respond_to?(:number)
          credit_card_or_reference.number
        else
          credit_card_or_reference.to_s
        end
      end
    end
  end
end
