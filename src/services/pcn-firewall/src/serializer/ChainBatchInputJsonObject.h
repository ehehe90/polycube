/**
* firewall API generated from firewall.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* ChainBatchInputJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"

#include "ChainBatchInputRulesJsonObject.h"
#include <vector>

namespace polycube {
namespace service {
namespace model {


/// <summary>
///
/// </summary>
class  ChainBatchInputJsonObject : public JsonObjectBase {
 public:
  ChainBatchInputJsonObject();
  ChainBatchInputJsonObject(const nlohmann::json &json);
  ~ChainBatchInputJsonObject() final = default;
  nlohmann::json toJson() const final;


  /// <summary>
  ///
  /// </summary>
  const std::vector<ChainBatchInputRulesJsonObject>& getRules() const;
  void addChainBatchInputRules(ChainBatchInputRulesJsonObject value);
  bool rulesIsSet() const;
  void unsetRules();

 private:
  std::vector<ChainBatchInputRulesJsonObject> m_rules;
  bool m_rulesIsSet;
};

}
}
}
